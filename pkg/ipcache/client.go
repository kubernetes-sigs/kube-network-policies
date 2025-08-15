/*
Copyright 2025 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package ipcache

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"
	"google.golang.org/protobuf/proto"
	"k8s.io/klog/v2"

	"sigs.k8s.io/kube-network-policies/pkg/api"
)

const (
	maxRetries     = 10
	initialBackoff = 1 * time.Second
	maxBackoff     = 30 * time.Second
)

// Client is a consumer of the distributed IP cache. It synchronizes a local
// Store with a remote ipcache server (Tracker or CacheProxy).
type Client struct {
	Store
	etcdClient *clientv3.Client
	syncStore  SyncMetadataStore
	readyChan  chan struct{}
	readyOnce  sync.Once
	errChan    chan error

	listenURL    string
	syncCallback func()
	nodeName     string
}

var _ Store = &Client{}
var _ api.PodInfoProvider = &Client{}

// NewClient creates a new ipcache client. It blocks until the initial synchronization
// is complete or the context is cancelled. A background goroutine is started to
// keep the local store synchronized with the remote endpoint.
//
// - ctx: Context for controlling the creation and background synchronization.
// - endpoint: The address of the upstream Tracker or CacheProxy.
// - tlsConfig: TLS configuration for connecting to the endpoint.
// - store: The local store to be kept in sync (e.g., *LRUStore or *EtcdStore).
// - syncStore: The store for persisting synchronization metadata (e.g., *BoltStore or *EtcdStore).
func NewClient(ctx context.Context, listenURL string, tlsConfig *tls.Config, store Store, syncStore SyncMetadataStore, nodeName string) (*Client, error) {
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{listenURL},
		DialTimeout: 5 * time.Second,
		TLS:         tlsConfig,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create etcd client: %w", err)
	}

	// Perform a quick health check to ensure the server is reachable.
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := cli.Status(checkCtx, listenURL); err != nil {
		cli.Close()
		return nil, fmt.Errorf("failed to connect to etcd server for initial health check: %w", err)
	}

	c := &Client{
		etcdClient:   cli,
		Store:        store,
		syncStore:    syncStore,
		readyChan:    make(chan struct{}),
		errChan:      make(chan error, 1),
		listenURL:    listenURL,
		syncCallback: func() {}, // no-op callback by default
		nodeName:     nodeName,
	}

	go c.run(ctx)

	// Wait for the client to be ready or for the context to be cancelled.
	select {
	case <-c.readyChan:
		return c, nil
	case err := <-c.Err():
		return nil, fmt.Errorf("client setup failed: %w", err)
	case <-ctx.Done():
		c.Close()
		return nil, ctx.Err()
	}
}

// SetSyncCallback sets a function to be called when the cache is updated.
func (c *Client) SetSyncCallback(callback func()) {
	c.syncCallback = callback
}

// Run starts the main synchronization loop. This function will block until the context is cancelled
// and will handle reconnects and retries internally.
func (c *Client) run(ctx context.Context) {
	defer close(c.errChan)
	var retries int
	for {
		if ctx.Err() != nil {
			klog.Infof("Context cancelled, stopping sync loop: %v", ctx.Err())
			return
		}

		// wasSuccessful tracks if we had a working connection before it failed.
		wasSuccessful, err := c.startWatch(ctx)

		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			klog.Info("Sync process stopped cleanly due to context cancellation.")
			return
		}
		if err == nil {
			klog.Info("Sync process stopped cleanly.")
			return
		}

		klog.Errorf("Sync process failed: %v", err)

		if wasSuccessful {
			retries = 0 // Reset retries if the connection was previously stable.
		} else {
			retries++
		}

		if retries >= maxRetries {
			klog.Errorf("Sync failed after %d consecutive attempts, giving up.", maxRetries)
			c.errChan <- err
			return
		}

		backoff := time.Duration(math.Pow(2, float64(retries))) * initialBackoff
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
		klog.Infof("Will retry sync in %s", backoff)
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return
		}
	}
}

// Err returns a channel that will receive a fatal error if the client's
// background synchronization fails permanently. The channel is closed when
// the client shuts down cleanly.
func (c *Client) Err() <-chan error {
	return c.errChan
}

// Close gracefully shuts down the client's connection to the etcd server.
func (c *Client) Close() error {
	_ = c.Store.Close()
	return c.etcdClient.Close()
}

// startWatch is the core logic for syncing and watching for changes.
func (c *Client) startWatch(ctx context.Context) (bool, error) {
	meta, err := c.syncStore.GetSyncMetadata()
	if err != nil {
		klog.Errorf("Failed to read sync metadata: %v", err)
	}

	statusResp, err := c.etcdClient.Status(ctx, c.listenURL)
	if err != nil {
		return false, fmt.Errorf("could not get server status: %w", err)
	}

	if meta.Revision == 0 || meta.ClusterID != statusResp.Header.ClusterId || meta.MemberID != statusResp.Header.MemberId {
		klog.Infof("Performing full sync. Reason: revision=%d, clusterID changed (%d -> %d), memberID changed (%d -> %d)",
			meta.Revision, meta.ClusterID, statusResp.Header.ClusterId, meta.MemberID, statusResp.Header.MemberId)
		if err := c.fullSync(ctx); err != nil {
			return false, fmt.Errorf("full sync failed: %w", err)
		}
		if c.syncCallback != nil {
			c.syncCallback()
		}

		// Reload metadata after the full sync.
		meta, err = c.syncStore.GetSyncMetadata()
		if err != nil {
			klog.Errorf("Failed to read sync metadata after full sync: %v", err)
		}
	}

	// The client is now considered synchronized and ready.
	c.readyOnce.Do(func() { close(c.readyChan) })

	watchChan := c.etcdClient.Watch(ctx, dataPrefixName+"/", clientv3.WithPrefix(), clientv3.WithRev(meta.Revision+1))
	klog.Infof("Starting watch from revision %d", meta.Revision+1)

	for resp := range watchChan {
		klog.V(7).Infof("watch response: %s", resp.Header.String())
		if err := resp.Err(); err != nil {
			return true, err // The connection was successful, but the watch failed.
		}

		// Check for compaction: if our revision is gone, we must resync.
		if resp.CompactRevision > 0 && meta.Revision < resp.CompactRevision {
			klog.Warningf("Required revision %d has been compacted (latest is %d). Triggering full sync.", meta.Revision, resp.CompactRevision)
			return true, fmt.Errorf("required revision %d has been compacted (latest is %d)", meta.Revision, resp.CompactRevision) // Returning an error triggers the retry loop which will call fullSync.
		}

		if err := c.processEvents(resp.Events, resp.Header.Revision); err != nil {
			return true, fmt.Errorf("failed to process events: %w", err)
		}
	}

	return true, ctx.Err() // Watch channel closed, likely due to context cancellation.
}

// fullSync performs a complete data fetch and atomically replaces the local store's content.
func (c *Client) fullSync(ctx context.Context) error {
	start := time.Now()
	klog.V(0).Info("Performing full sync")
	defer func() {
		klog.V(0).Infof("Full sync completed in %s", time.Since(start))
	}()
	resp, err := c.etcdClient.Get(ctx, dataPrefixName+"/", clientv3.WithPrefix())
	if err != nil {
		return err
	}
	klog.V(0).Infof("Get full sync %d records in %s", len(resp.Kvs), time.Since(start))

	// 1. Clear the local store completely.
	if err := c.Clear(); err != nil {
		return fmt.Errorf("failed to clear local store: %w", err)
	}

	// 2. Populate the store with the new data.
	for _, kv := range resp.Kvs {
		var podInfo api.PodInfo
		if err := proto.Unmarshal(kv.Value, &podInfo); err == nil {
			ip, err := keyToIP(kv.Key)
			if err != nil {
				klog.Warningf("Skipping invalid key string: %s bytes: %v from server: %v", string(kv.Key), kv.Key, err)
				continue
			}
			if err := c.Upsert(ip, &podInfo); err != nil {
				klog.Errorf("Failed to upsert record during full sync for IP %s: %v", ip, err)
			}
		}
	}

	// 3. Update the sync metadata to reflect the new state.
	return c.syncStore.SetSyncMetadata(&SyncMetadata{
		Revision:  resp.Header.Revision,
		ClusterID: resp.Header.ClusterId,
		MemberID:  resp.Header.MemberId,
	})
}

// processEvents applies a batch of events to the store and updates the sync revision.
func (c *Client) processEvents(events []*clientv3.Event, revision int64) error {
	needsSync := false
	for _, event := range events {
		ip, err := keyToIP(event.Kv.Key)
		if err != nil {
			klog.Warningf("Skipping event with invalid key string: %s bytes: %v from server: %v", string(event.Kv.Key), event.Kv.Key, err)
			continue
		}
		switch event.Type {
		case mvccpb.PUT:
			var podInfo api.PodInfo
			if err := proto.Unmarshal(event.Kv.Value, &podInfo); err == nil {
				if podInfo.Node != nil && podInfo.Node.Name == c.nodeName {
					needsSync = true
				}
				klog.V(7).Infof("Upserted IP %s with Pod %s/%s", ip, podInfo.Namespace.Name, podInfo.Name)
				if err := c.Upsert(ip, &podInfo); err != nil {
					return err // Return error to trigger reconnect
				}
			}
		case mvccpb.DELETE:
			// For deletes, we check the old value if it's a local pod
			if info, ok := c.GetPodInfoByIP(ip); ok && info.Node != nil && info.Node.Name == c.nodeName {
				needsSync = true
			}
			klog.V(7).Infof("Deleted IP %s", ip)
			if err := c.Delete(ip); err != nil {
				return err // Return error to trigger reconnect
			}
		}
	}

	if c.syncCallback != nil && needsSync {
		c.syncCallback()
	}

	// Persist the latest revision.
	meta, err := c.syncStore.GetSyncMetadata()
	if err != nil {
		return err
	}
	if revision > meta.Revision {
		meta.Revision = revision
		return c.syncStore.SetSyncMetadata(meta)
	}
	return nil
}
