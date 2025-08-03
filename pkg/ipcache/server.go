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
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/server/v3/embed"
	"google.golang.org/protobuf/proto"
	"k8s.io/klog/v2"
)

const internalSocketName = "ipcache-internal.sock"

// Server is the main struct for the IPCache server.
type Server struct {
	etcd   *embed.Etcd
	client *clientv3.Client
}

// ipToBinaryKey converts a cluster ID and IP address into a binary key.
// The format is /<clusterid>/ipv4/<4-byte-ip> or /<clusterid>/ipv6/<16-byte-ip>.
func ipToBinaryKey(clusterID string, ipStr string) (string, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", fmt.Errorf("invalid IP address format: %s", ipStr)
	}

	if ipV4 := ip.To4(); ipV4 != nil {
		// It's an IPv4 address, use its 4-byte representation.
		prefix := fmt.Sprintf("/%s/ipv4/", clusterID)
		return prefix + string(ipV4), nil
	}

	if ipV6 := ip.To16(); ipV6 != nil {
		// It's an IPv6 address, use its 16-byte representation.
		prefix := fmt.Sprintf("/%s/ipv6/", clusterID)
		return prefix + string(ipV6), nil
	}

	return "", fmt.Errorf("unsupported IP format: %s", ip.String())
}

// NewServer creates and starts a new IPCache server.
func NewServer(listenURL string, etcdDir string) (*Server, error) {
	internalSocketPath := filepath.Join(etcdDir, internalSocketName)
	if err := os.RemoveAll(internalSocketPath); err != nil {
		return nil, fmt.Errorf("failed to remove old internal socket file: %w", err)
	}

	allClientUrls := append([]string{"unix://" + internalSocketPath}, listenURL)
	parsedClientUrls := make([]url.URL, len(allClientUrls))

	for i, sURL := range allClientUrls {
		u, err := url.Parse(sURL)
		if err != nil {
			return nil, fmt.Errorf("failed to parse client url %s: %w", sURL, err)
		}
		parsedClientUrls[i] = *u
	}

	cfg := embed.NewConfig()
	cfg.Dir = etcdDir
	cfg.ListenClientUrls = parsedClientUrls
	cfg.ListenPeerUrls = []url.URL{}
	cfg.LogLevel = "error"

	e, err := embed.StartEtcd(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to start embedded etcd: %w", err)
	}

	select {
	case <-e.Server.ReadyNotify():
		klog.Infof("Embedded etcd is ready on %v", allClientUrls)
	case <-time.After(10 * time.Second):
		return nil, fmt.Errorf("etcd server took too long to start")
	}

	client, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{"unix://" + internalSocketPath},
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create etcd client: %w", err)
	}

	s := &Server{
		etcd:   e,
		client: client,
	}

	klog.Infof("IPCache server API is ready")

	return s, nil
}

// Upsert adds or updates a PodInfo record in the etcd store using Protobuf and a binary key.
func (s *Server) Upsert(ctx context.Context, clusterID string, ip string, record *PodInfo) error {
	key, err := ipToBinaryKey(clusterID, ip)
	if err != nil {
		return err
	}

	record.LastUpdated = time.Now().Unix()
	// Marshal using Protobuf
	data, err := proto.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal proto record: %w", err)
	}

	_, err = s.client.Put(ctx, key, string(data))
	if err != nil {
		return fmt.Errorf("etcd put failed: %w", err)
	}

	klog.Infof("Upserted record for IP %s in cluster %s", ip, clusterID)
	return nil
}

// Delete removes a record from the etcd store using a binary key.
func (s *Server) Delete(ctx context.Context, clusterID string, ip string) error {
	key, err := ipToBinaryKey(clusterID, ip)
	if err != nil {
		return err
	}

	_, err = s.client.Delete(ctx, key)
	if err != nil {
		return fmt.Errorf("etcd delete failed: %w", err)
	}

	klog.Infof("Deleted record for IP %s in cluster %s", ip, clusterID)
	return nil
}

// Close gracefully shuts down the server.
func (s *Server) Close() {
	klog.Infoln("Shutting down IPCache server...")
	if s.client != nil {
		s.client.Close()
	}
	if s.etcd != nil {
		s.etcd.Close()
	}
	klog.Infoln("Server shut down complete.")
}
