/*
Copyright 2026 The Kubernetes Authors.

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

package dht

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"sigs.k8s.io/kube-network-policies/pkg/api"
)

type testCluster struct {
	t       *testing.T
	nodes   map[string]*DHT
	cancels map[string]context.CancelFunc
	done    map[string]chan error
	order   []string
}

func newTestCluster(t *testing.T, count int, mutCfg func(nodeName string, cfg *Config)) *testCluster {
	t.Helper()
	tc := &testCluster{
		t:       t,
		nodes:   make(map[string]*DHT, count),
		cancels: make(map[string]context.CancelFunc, count),
		done:    make(map[string]chan error, count),
		order:   make([]string, 0, count),
	}

	for i := 1; i <= count; i++ {
		name := fmt.Sprintf("node-%d", i)
		cfg := Config{
			NodeName:          name,
			ListenAddress:     "127.0.0.1:0",
			ReplicationFactor: 3,
			RecordTTL:         30 * time.Second,
			CacheTTL:          150 * time.Millisecond,
			NegativeCacheTTL:  100 * time.Millisecond,
			CacheSize:         256,
			RPCTimeout:        500 * time.Millisecond,
		}
		if mutCfg != nil {
			mutCfg(name, &cfg)
		}
		node, err := New(cfg)
		if err != nil {
			t.Fatalf("New(%s) error = %v", name, err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		errCh := make(chan error, 1)
		go func() {
			errCh <- node.Run(ctx)
		}()
		waitUntil(t, 2*time.Second, name+" listener ready", func() bool {
			return node.ListenAddr() != ""
		})

		tc.nodes[name] = node
		tc.cancels[name] = cancel
		tc.done[name] = errCh
		tc.order = append(tc.order, name)
	}

	t.Cleanup(func() {
		for _, name := range tc.order {
			tc.stopNode(name)
		}
	})

	tc.broadcastMembers(tc.allMembers())
	return tc
}

func (tc *testCluster) stopNode(name string) {
	if cancel, ok := tc.cancels[name]; ok {
		cancel()
		delete(tc.cancels, name)
		<-tc.done[name]
	}
}

func (tc *testCluster) allMembers() []Member {
	out := make([]Member, 0, len(tc.order))
	for _, name := range tc.order {
		out = append(out, Member{
			NodeName: name,
			Address:  tc.nodes[name].ListenAddr(),
		})
	}
	return out
}

func (tc *testCluster) broadcastMembers(members []Member) {
	for _, n := range tc.nodes {
		n.UpdateMembers(members)
	}
}

func waitUntil(t *testing.T, timeout time.Duration, desc string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", desc)
}

func TestIntegration_PublishLookupMutationAndTombstone(t *testing.T) {
	tc := newTestCluster(t, 5, nil)

	const podIP = "10.244.5.10"
	tc.nodes["node-5"].Publish(podIP, &api.PodInfo{
		UID:       "uid-srv",
		Name:      "web",
		Namespace: &api.Namespace{Name: "prod"},
		Labels:    map[string]string{"app": "web", "v": "1"},
		IPs:       []string{podIP},
	})

	// node-1 resolves podIP over stdlib HTTP/2 (h2c).
	waitUntil(t, 2*time.Second, "node-1 to resolve published pod", func() bool {
		pod, ok, err := tc.nodes["node-1"].ResolvePodInfoByIP(context.Background(), podIP)
		return err == nil && ok && pod.Labels["v"] == "1"
	})

	// Label mutation on node-5 converges on node-1 after short CacheTTL (150ms).
	tc.nodes["node-5"].Publish(podIP, &api.PodInfo{
		UID:       "uid-srv",
		Name:      "web",
		Namespace: &api.Namespace{Name: "prod"},
		Labels:    map[string]string{"app": "web", "v": "2"},
		IPs:       []string{podIP},
	})
	waitUntil(t, 2*time.Second, "node-1 to see mutated label v=2 after CacheTTL", func() bool {
		pod, ok, err := tc.nodes["node-1"].ResolvePodInfoByIP(context.Background(), podIP)
		return err == nil && ok && pod.Labels["v"] == "2"
	})

	// Delete publishes tombstones; node-1 stops resolving podIP once CacheTTL expires.
	tc.nodes["node-5"].Delete(podIP)
	waitUntil(t, 2*time.Second, "node-1 to see deleted pod after CacheTTL", func() bool {
		_, ok, err := tc.nodes["node-1"].ResolvePodInfoByIP(context.Background(), podIP)
		return err == nil && !ok
	})
}

// TestIntegration_TombstoneSuppressesLaggingReplica verifies that if one
// replica missed a tombstone Put, readers querying the ring still suppress
// the lagging replica's stale ALIVE record instead of resurrecting the pod.
func TestIntegration_TombstoneSuppressesLaggingReplica(t *testing.T) {
	tc := newTestCluster(t, 5, nil)

	const ip = "10.244.2.77"
	targets := tc.nodes["node-1"].ring.Load().Targets(ip, 3)
	if len(targets) != 3 {
		t.Fatalf("expected 3 targets, got %d", len(targets))
	}

	// Manually inject: primary has TOMBSTONE seq=20, replica #2 has stale ALIVE seq=10.
	now := time.Now()
	pb := mustMarshalPod(t, "uid-dead", "dev", "dead", "node-5", map[string]string{"app": "dead"}, ip)
	if _, _, err := tc.nodes[targets[0].NodeName].store.Put(Record{
		IP: ip, OwnerNode: "node-5", Seq: 20, Tombstone: true, TTLMS: 30_000,
	}, now); err != nil {
		t.Fatalf("putting tombstone: %v", err)
	}
	if _, _, err := tc.nodes[targets[1].NodeName].store.Put(Record{
		IP: ip, OwnerNode: "node-5", Seq: 10, TTLMS: 30_000, PodInfoPB: pb,
	}, now); err != nil {
		t.Fatalf("putting stale alive: %v", err)
	}

	// Pick a reader node outside targets and verify it gets NOT FOUND (not dead pod!).
	var reader *DHT
	for _, name := range tc.order {
		if name != targets[0].NodeName && name != targets[1].NodeName && name != targets[2].NodeName {
			reader = tc.nodes[name]
			break
		}
	}
	pod, found, err := reader.ResolvePodInfoByIP(context.Background(), ip)
	if err != nil || found || pod != nil {
		t.Fatalf("ResolvePodInfoByIP(%s) = (%v, %v, %v), want tombstone suppression (nil, false, nil)", ip, pod, found, err)
	}
}

// TestIntegration_ReplicaFailoverAndOutageError verifies:
//   - killing the primary replica falls back cleanly to replica #2
//   - killing ALL replicas returns an error (and does NOT negative-cache) so FailOpen works
func TestIntegration_ReplicaFailoverAndOutageError(t *testing.T) {
	tc := newTestCluster(t, 5, nil)

	const ip = "10.244.3.88"
	tc.nodes["node-3"].Publish(ip, &api.PodInfo{
		UID:       "uid-ha",
		Name:      "ha",
		Namespace: &api.Namespace{Name: "prod"},
		Labels:    map[string]string{"app": "ha"},
		IPs:       []string{ip},
	})

	targets := tc.nodes["node-1"].ring.Load().Targets(ip, 3)
	var readerName string
	for _, name := range tc.order {
		if name != targets[0].NodeName && name != targets[1].NodeName && name != targets[2].NodeName {
			readerName = name
			break
		}
	}
	reader := tc.nodes[readerName]

	// Wait until all 3 replicas hold the record.
	waitUntil(t, 2*time.Second, "all 3 replicas populated", func() bool {
		for _, target := range targets {
			if len(tc.nodes[target.NodeName].store.Get(ip, time.Now())) == 0 {
				return false
			}
		}
		return true
	})

	// Stop primary replica without updating ring -> sequential fallback hits replica #2.
	tc.stopNode(targets[0].NodeName)
	pod, found, err := reader.ResolvePodInfoByIP(context.Background(), ip)
	if err != nil || !found || pod.UID != "uid-ha" {
		t.Fatalf("after primary stop got (%v, %v, %v), want uid-ha", pod, found, err)
	}

	// Stop all remaining replicas and clear cache -> must return error, NOT (nil, false, nil).
	tc.stopNode(targets[1].NodeName)
	tc.stopNode(targets[2].NodeName)
	reader.cache.Delete(ip)
	if _, _, err := reader.ResolvePodInfoByIP(context.Background(), ip); err == nil {
		t.Fatalf("expected error when all replicas are unreachable so FailOpen can apply")
	}
}

// TestIntegration_RollingUpdatePreservesWorkloadRecords verifies that removing
// an agent temporarily from membership (DaemonSet rolling restart) does NOT
// wipe healthy workload pod records owned by that node.
func TestIntegration_RollingUpdatePreservesWorkloadRecords(t *testing.T) {
	tc := newTestCluster(t, 4, nil)

	const ip = "10.244.4.44"
	tc.nodes["node-4"].Publish(ip, &api.PodInfo{
		UID:       "uid-44",
		Name:      "workload",
		Namespace: &api.Namespace{Name: "prod"},
		Labels:    map[string]string{"app": "workload"},
		IPs:       []string{ip},
	})

	waitUntil(t, 2*time.Second, "node-1 to resolve node-4 pod", func() bool {
		pod, ok, err := tc.nodes["node-1"].ResolvePodInfoByIP(context.Background(), ip)
		return err == nil && ok && pod.UID == "uid-44"
	})

	// Simulate node-4's agent restarting (absent from EndpointSlice briefly).
	var withoutNode4 []Member
	for _, m := range tc.allMembers() {
		if m.NodeName != "node-4" {
			withoutNode4 = append(withoutNode4, m)
		}
	}
	tc.broadcastMembers(withoutNode4)
	tc.nodes["node-1"].cache.Delete(ip)

	// Workload pod on node-4 must STILL resolve from surviving replicas until RecordTTL!
	pod, ok, err := tc.nodes["node-1"].ResolvePodInfoByIP(context.Background(), ip)
	if err != nil || !ok || pod.UID != "uid-44" {
		t.Fatalf("rolling update caused blackout for healthy workload pod: got (%v, %v, %v)", pod, ok, err)
	}
}

// TestIntegration_BackwardClockSeqRecovery verifies that if replicas hold a
// higher Seq than a restarted owner node, the owner advances its Seq past
// MaxSeq and succeeds automatically.
func TestIntegration_BackwardClockSeqRecovery(t *testing.T) {
	tc := newTestCluster(t, 3, nil)

	const ip = "10.244.1.22"
	const futureSeq = uint64(1 << 62)
	pbOld := mustMarshalPod(t, "uid-old", "dev", "old", "node-1", map[string]string{"v": "old"}, ip)
	for _, name := range tc.order {
		_, _, _ = tc.nodes[name].store.Put(Record{
			IP: ip, OwnerNode: "node-1", Seq: futureSeq, TTLMS: 30_000, PodInfoPB: pbOld,
		}, time.Now())
	}

	// Simulate restarted node-1 whose clock stepped backward (seq=10 < futureSeq).
	tc.nodes["node-1"].seq.Store(10)
	tc.nodes["node-1"].Publish(ip, &api.PodInfo{
		UID:       "uid-new",
		Name:      "new",
		Namespace: &api.Namespace{Name: "dev"},
		Labels:    map[string]string{"v": "new"},
		IPs:       []string{ip},
	})

	waitUntil(t, 2*time.Second, "node-2 to observe recovered record with bumped Seq", func() bool {
		tc.nodes["node-2"].cache.Delete(ip)
		pod, ok, err := tc.nodes["node-2"].ResolvePodInfoByIP(context.Background(), ip)
		return err == nil && ok && pod.UID == "uid-new"
	})
}

// TestIntegration_MTLSAndRequireNodeCert verifies TLS 1.3 mTLS over HTTP/2,
// CN=system:node:<name> ownership enforcement, and fail-closed RequireNodeCert.
func TestIntegration_MTLSAndRequireNodeCert(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey, caFile := generateTestCA(t, dir)
	cert1, key1 := generateTestCert(t, dir, caCert, caKey, "system:node:node-1")
	cert2, key2 := generateTestCert(t, dir, caCert, caKey, "system:node:node-2")
	certOther, keyOther := generateTestCert(t, dir, caCert, caKey, "kube-proxy")

	srv1, cli1, err := NewTLSConfigs(caFile, cert1, key1)
	if err != nil {
		t.Fatalf("NewTLSConfigs(node-1): %v", err)
	}
	srv2, cli2, err := NewTLSConfigs(caFile, cert2, key2)
	if err != nil {
		t.Fatalf("NewTLSConfigs(node-2): %v", err)
	}
	_, cliOther, err := NewTLSConfigs(caFile, certOther, keyOther)
	if err != nil {
		t.Fatalf("NewTLSConfigs(other): %v", err)
	}

	tc := newTestCluster(t, 2, func(name string, cfg *Config) {
		cfg.ReplicationFactor = 2
		cfg.RequireNodeCert = true
		if name == "node-1" {
			cfg.ServerTLS = srv1
			cfg.ClientTLS = cli1
		} else {
			cfg.ServerTLS = srv2
			cfg.ClientTLS = cli2
		}
	})

	// Legitimate mTLS Publish + Lookup succeeds.
	const ip = "10.244.1.99"
	tc.nodes["node-1"].Publish(ip, &api.PodInfo{
		UID:       "uid-tls",
		Name:      "secure",
		Namespace: &api.Namespace{Name: "prod"},
		Labels:    map[string]string{"tls": "ok"},
		IPs:       []string{ip},
	})
	waitUntil(t, 2*time.Second, "node-2 mTLS lookup", func() bool {
		pod, ok, err := tc.nodes["node-2"].ResolvePodInfoByIP(context.Background(), ip)
		return err == nil && ok && pod.UID == "uid-tls"
	})

	// Spoofing attempt 1: node-1 tries to Put a record claiming OwnerNode="node-2".
	_, err = tc.nodes["node-1"].remotePut(context.Background(), tc.nodes["node-2"].ListenAddr(), []Record{{
		IP: "10.244.2.50", OwnerNode: "node-2", Seq: 1, Tombstone: true, TTLMS: 10_000,
	}})
	if err == nil {
		t.Fatalf("expected 403 Forbidden for spoofed OwnerNode, got nil")
	}

	// Spoofing attempt 2: CA-signed non-node cert ("kube-proxy") rejected under RequireNodeCert=true.
	otherNode, err := New(Config{
		NodeName:  "kube-proxy",
		ClientTLS: cliOther,
	})
	if err != nil {
		t.Fatalf("New(other): %v", err)
	}
	_, err = otherNode.remotePut(context.Background(), tc.nodes["node-2"].ListenAddr(), []Record{{
		IP: "10.244.2.51", OwnerNode: "node-2", Seq: 1, Tombstone: true, TTLMS: 10_000,
	}})
	if err == nil {
		t.Fatalf("expected 403 Forbidden for non-node CA certificate under RequireNodeCert")
	}
}

func TestIntegration_ConcurrentSingleflightLookup(t *testing.T) {
	tc := newTestCluster(t, 5, nil)

	const ip = "10.244.2.200"
	tc.nodes["node-2"].Publish(ip, &api.PodInfo{
		UID:       "uid-sf",
		Name:      "concurrent",
		Namespace: &api.Namespace{Name: "prod"},
		Labels:    map[string]string{"app": "sf"},
		IPs:       []string{ip},
	})
	waitUntil(t, 2*time.Second, "initial publish visible", func() bool {
		_, ok, err := tc.nodes["node-3"].ResolvePodInfoByIP(context.Background(), ip)
		return err == nil && ok
	})

	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pod, ok, err := tc.nodes["node-1"].ResolvePodInfoByIP(context.Background(), ip)
			if err != nil || !ok || pod == nil || pod.UID != "uid-sf" {
				errs <- fmt.Errorf("got (%v, %v, %v), want uid-sf", pod, ok, err)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func generateTestCA(t *testing.T, dir string) (*x509.Certificate, *ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-dht-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing CA cert: %v", err)
	}
	caFile := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("writing CA cert: %v", err)
	}
	return cert, key, caFile
}

func generateTestCert(t *testing.T, dir string, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, cn string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("generating serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("creating cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling key: %v", err)
	}
	base := filepath.Join(dir, fmt.Sprintf("%d", serial.Int64()))
	certFile = base + ".crt"
	keyFile = base + ".key"
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("writing cert: %v", err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("writing key: %v", err)
	}
	return certFile, keyFile
}
