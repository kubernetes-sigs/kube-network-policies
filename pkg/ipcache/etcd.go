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
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/server/v3/embed"
	"google.golang.org/protobuf/proto"
	"k8s.io/klog/v2"

	"sigs.k8s.io/kube-network-policies/pkg/api"
)

const (
	internalSocketName = "ipcache-internal.sock"

	// Prefix names
	dataPrefixName   = "ipcache_data"
	metaPrefixName   = "ipcache_meta"
	timeoutOperation = 5 * time.Second
	timeoutList      = 300 * time.Second
	timeoutStartup   = 60 * time.Second
)

func ipToKey(ip string) (string, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return "", fmt.Errorf("invalid IP address %s: %w", ip, err)
	}
	return dataPrefixName + "/" + addr.String(), nil
}

func keyToIP(key []byte) (string, error) {
	prefix := []byte(dataPrefixName + "/")

	if !bytes.HasPrefix(key, prefix) {
		return "", fmt.Errorf("key %q does not have the expected prefix %q", key, prefix)
	}
	ipStr := string(bytes.TrimPrefix(key, prefix))

	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return "", fmt.Errorf("invalid IP address %s: %w", ipStr, err)
	}
	return addr.String(), nil
}

// EtcdStore implements the Store and Watcher interfaces using an embedded etcd server.
type EtcdStore struct {
	etcd      *embed.Etcd
	client    *clientv3.Client
	listenURL string
}

var _ Store = &EtcdStore{}
var _ SyncMetadataStore = &EtcdStore{}
var _ api.PodInfoProvider = &EtcdStore{}

// EtcdOption configures the embedded etcd server.
type EtcdOption func(*embed.Config)

// WithTLS configures the server to use TLS for client connections.
func WithTLS(certFile, keyFile, clientCAFile string) EtcdOption {
	return func(cfg *embed.Config) {
		cfg.ClientTLSInfo.CertFile = certFile
		cfg.ClientTLSInfo.KeyFile = keyFile
		cfg.ClientTLSInfo.TrustedCAFile = clientCAFile
		cfg.ClientTLSInfo.ClientCertAuth = true // Require client certs
	}
}

// NewEtcdStore creates and starts a new EtcdStore.
func NewEtcdStore(listenURL, etcdDir string, opts ...EtcdOption) (*EtcdStore, error) {
	// Ensure the provided path is a valid directory.
	if stat, err := os.Stat(etcdDir); err != nil {
		return nil, fmt.Errorf("etcd directory check failed: %w", err)
	} else if !stat.IsDir() {
		return nil, fmt.Errorf("etcd path is not a directory: %s", etcdDir)
	}
	internalSocketPath := filepath.Join(etcdDir, internalSocketName)
	if err := os.RemoveAll(internalSocketPath); err != nil {
		return nil, fmt.Errorf("failed to remove old internal socket file: %w", err)
	}

	cfg := embed.NewConfig()
	cfg.Dir = etcdDir
	cfg.LogLevel = "error"
	// Disable peer communication as we're running a single-member cluster.
	cfg.ListenPeerUrls = []url.URL{}

	for _, opt := range opts {
		opt(cfg)
	}

	scheme := "http"
	if cfg.ClientTLSInfo.CertFile != "" {
		scheme = "https"
	}

	parsedListenURL, err := url.Parse(listenURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse listen url %s: %w", listenURL, err)
	}
	parsedListenURL.Scheme = scheme

	// The server listens on both the external URL and an internal Unix socket for efficiency.
	clientURLs := []string{"unix://" + internalSocketPath, parsedListenURL.String()}
	parsedClientUrls := make([]url.URL, len(clientURLs))
	for i, sURL := range clientURLs {
		u, err := url.Parse(sURL)
		if err != nil {
			return nil, fmt.Errorf("failed to parse client url %s: %w", sURL, err)
		}
		parsedClientUrls[i] = *u
	}
	cfg.ListenClientUrls = parsedClientUrls

	e, err := embed.StartEtcd(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to start embedded etcd: %w", err)
	}

	select {
	case <-e.Server.ReadyNotify():
		klog.Infof("Embedded etcd is ready and listening on %v", clientURLs)
	case <-time.After(timeoutStartup):
		e.Close()
		return nil, fmt.Errorf("etcd server took too long to start")
	}

	// The internal client connects via the Unix socket for performance.
	client, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{"unix://" + internalSocketPath},
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		e.Close()
		return nil, fmt.Errorf("failed to create internal etcd client: %w", err)
	}
	// Perform a quick health check to ensure the server is reachable before proceeding.
	// This provides fast feedback on connection issues.
	checkCtx, cancel := context.WithTimeout(context.Background(), timeoutOperation)
	defer cancel()
	// Using Status is an idiomatic way to confirm connectivity to a specific endpoint.
	_, err = client.Status(checkCtx, "unix://"+internalSocketPath)
	if err != nil {
		e.Close()
		return nil, fmt.Errorf("failed to connect to etcd server for initial health check: %w", err)
	}

	return &EtcdStore{
		etcd:      e,
		client:    client,
		listenURL: listenURL,
	}, nil
}

func (s *EtcdStore) GetPodInfoByIP(ip string) (*api.PodInfo, bool) {
	klog.V(7).Infof("Get(%s)", ip)
	key, err := ipToKey(ip)
	if err != nil {
		return nil, false
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeoutOperation)
	defer cancel()

	resp, err := s.client.Get(ctx, key)
	if err != nil || len(resp.Kvs) == 0 {
		return nil, false
	}

	var podInfo api.PodInfo
	if err := proto.Unmarshal(resp.Kvs[0].Value, &podInfo); err != nil {
		return nil, false
	}
	return &podInfo, true
}

func (s *EtcdStore) Upsert(ip string, info *api.PodInfo) error {
	klog.V(7).Infof("Upsert(%s)", ip)
	key, err := ipToKey(ip)
	if err != nil {
		return err
	}

	data, err := proto.Marshal(info)
	if err != nil {
		return fmt.Errorf("failed to marshal proto record: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeoutOperation)
	defer cancel()

	_, err = s.client.Put(ctx, key, string(data))
	return err
}

func (s *EtcdStore) Delete(ip string) error {
	klog.V(7).Infof("Delete(%s)", ip)
	key, err := ipToKey(ip)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeoutOperation)
	defer cancel()

	_, err = s.client.Delete(ctx, key)
	return err
}

func (s *EtcdStore) List() ([]*api.PodInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeoutList)
	defer cancel()

	resp, err := s.client.Get(ctx, dataPrefixName+"/", clientv3.WithPrefix())
	if err != nil {
		return nil, err
	}

	var infos []*api.PodInfo
	for _, kv := range resp.Kvs {
		var podInfo api.PodInfo
		if err := proto.Unmarshal(kv.Value, &podInfo); err == nil {
			infos = append(infos, &podInfo)
		}
	}
	return infos, nil
}

// Clear the entire store (metadata included)
func (s *EtcdStore) Clear() error {
	var errs []error
	_, err := s.client.Delete(context.Background(), dataPrefixName+"/", clientv3.WithPrefix())
	if err != nil {
		errs = append(errs, err)
	}
	_, err = s.client.Delete(context.Background(), metaPrefixName+"/", clientv3.WithPrefix())
	if err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (s *EtcdStore) Close() error {
	s.client.Close()
	select {
	case err := <-s.etcd.Err():
		return err
	default:
		s.etcd.Close()
	}
	return nil
}

func (s *EtcdStore) GetServerIdentity(ctx context.Context) (uint64, uint64, error) {
	// Status can be slow; use a short timeout. The MemberId is the most important.
	statusCtx, cancel := context.WithTimeout(ctx, timeoutOperation)
	defer cancel()

	resp, err := s.client.Status(statusCtx, s.listenURL)
	if err != nil {
		return 0, 0, err
	}
	return resp.Header.ClusterId, resp.Header.MemberId, nil
}

func (s *EtcdStore) GetSyncMetadata() (*SyncMetadata, error) {
	meta := &SyncMetadata{}
	ctx, cancel := context.WithTimeout(context.Background(), timeoutOperation)
	defer cancel()

	keys := []string{
		string(lastRevisionKey),
		string(lastClusterIDKey),
		string(lastMemberIDKey),
	}

	// Fetch all metadata keys in a single request
	for _, key := range keys {
		resp, err := s.client.Get(ctx, metaPrefixName+"/"+key)
		if err != nil {
			return nil, fmt.Errorf("failed to get metadata key %s: %w", key, err)
		}
		if len(resp.Kvs) == 0 {
			continue
		}
		val := resp.Kvs[0].Value
		switch key {
		case string(lastRevisionKey):
			meta.Revision = int64(binary.BigEndian.Uint64(val))
		case string(lastClusterIDKey):
			meta.ClusterID = binary.BigEndian.Uint64(val)
		case string(lastMemberIDKey):
			meta.MemberID = binary.BigEndian.Uint64(val)
		}
	}
	return meta, nil
}

func (s *EtcdStore) SetSyncMetadata(meta *SyncMetadata) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeoutOperation)
	defer cancel()

	revBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(revBytes, uint64(meta.Revision))

	clusterIDBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(clusterIDBytes, meta.ClusterID)

	memberIDBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(memberIDBytes, meta.MemberID)

	// Use a transaction to ensure all metadata is written atomically
	_, err := s.client.Txn(ctx).Then(
		clientv3.OpPut(metaPrefixName+"/"+string(lastRevisionKey), string(revBytes)),
		clientv3.OpPut(metaPrefixName+"/"+string(lastClusterIDKey), string(clusterIDBytes)),
		clientv3.OpPut(metaPrefixName+"/"+string(lastMemberIDKey), string(memberIDBytes)),
	).Commit()

	return err
}
