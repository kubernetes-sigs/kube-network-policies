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
	"fmt"
	"time"

	"go.etcd.io/bbolt"
	"go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"
	"google.golang.org/protobuf/proto"
	"k8s.io/klog/v2"
)

var bucketName = []byte("ipcache")

// Client is a consumer of the distributed IP cache.
type Client struct {
	etcdClient *clientv3.Client
	db         *bbolt.DB
}

// NewClient creates a new client and starts syncing with the server.
func NewClient(ctx context.Context, serverAddress, dbPath string) (*Client, error) {
	// 1. Connect to the etcd server.
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{serverAddress},
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to etcd: %w", err)
	}

	// 2. Open the bbolt database.
	db, err := bbolt.Open(dbPath, 0600, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open db: %w", err)
	}

	// 3. Create the bucket if it doesn't exist.
	err = db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(bucketName)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create bucket: %w", err)
	}

	c := &Client{
		etcdClient: cli,
		db:         db,
	}

	// 4. Start a goroutine to continuously sync from the etcd server to our local db.
	go c.syncLoop(ctx)

	klog.Infoln("IPCache client connected and starting to sync.")
	return c, nil
}

// syncLoop watches for changes from the etcd server and updates the local db.
func (c *Client) syncLoop(ctx context.Context) {
	// Initial fetch
	resp, err := c.etcdClient.Get(ctx, "", clientv3.WithPrefix())
	if err != nil {
		klog.Infof("Initial fetch failed: %v", err)
	} else {
		err = c.db.Update(func(tx *bbolt.Tx) error {
			b := tx.Bucket(bucketName)
			for _, kv := range resp.Kvs {
				key := string(kv.Key)
				var rec PodInfo
				if err := proto.Unmarshal(kv.Value, &rec); err != nil {
					klog.Infof("Error unmarshalling record for key %s: %v", key, err)
					continue
				}
				if err := b.Put([]byte(key), kv.Value); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			klog.Infof("Initial db update failed: %v", err)
		}
	}

	watchChan := c.etcdClient.Watch(ctx, "", clientv3.WithPrefix())

	for resp := range watchChan {
		if err := resp.Err(); err != nil {
			klog.Infof("Watch error: %v", err)
			continue
		}

		err = c.db.Update(func(tx *bbolt.Tx) error {
			b := tx.Bucket(bucketName)
			for _, event := range resp.Events {
				key := string(event.Kv.Key)

				switch event.Type {
				case mvccpb.PUT:
					var rec PodInfo
					if err := proto.Unmarshal(event.Kv.Value, &rec); err != nil {
						klog.Infof("Error unmarshalling record for key %s: %v", key, err)
						continue
					}
					if err := b.Put([]byte(key), event.Kv.Value); err != nil {
						return err
					}
					klog.V(2).Infof("Client cache updated for pod: %s", rec.PodName)

				case mvccpb.DELETE:
					if err := b.Delete([]byte(key)); err != nil {
						return err
					}
					klog.V(2).Infof("Client cache deleted key: %s", key)
				}
			}
			return nil
		})
		if err != nil {
			klog.Infof("DB update failed: %v", err)
		}
	}
	klog.Info("Client sync loop stopped.")
}

// Get looks up a PodInfo from the local cache.
func (c *Client) Get(clusterID, ip string) (*PodInfo, bool) {
	key, err := ipToBinaryKey(clusterID, ip)
	if err != nil {
		return nil, false
	}

	var podInfo PodInfo
	err = c.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketName)
		val := b.Get([]byte(key))
		if val == nil {
			return fmt.Errorf("not found")
		}
		return proto.Unmarshal(val, &podInfo)
	})

	if err != nil {
		return nil, false
	}

	return &podInfo, true
}

// List returns all records from the local cache.
func (c *Client) List() []*PodInfo {
	var records []*PodInfo
	c.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketName)
		c := b.Cursor()

		for k, v := c.First(); k != nil; k, v = c.Next() {
			var podInfo PodInfo
			if err := proto.Unmarshal(v, &podInfo); err == nil {
				records = append(records, &podInfo)
			}
		}
		return nil
	})
	return records
}

// Close shuts down the client connection.
func (c *Client) Close() {
	if c.etcdClient != nil {
		c.etcdClient.Close()
	}
	if c.db != nil {
		c.db.Close()
	}
}
