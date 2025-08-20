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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/time/rate"
	"sigs.k8s.io/kube-network-policies/pkg/api"
)

const (
	testClusterID  = "test-cluster"
	testClusterID2 = "test-cluster-2"
)

// Helper to get a free TCP port for the server to listen on.
func getFreePort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return 0, err
	}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// Helper to wait for a condition to be true, with a timeout.
func waitForCondition(t *testing.T, msg string, condition func() bool, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal(msg)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// generateTestTLS creates a self-signed certificate and key for testing.
// It returns the paths to the CA, cert, and key files, and a client TLS config.
func generateTestTLS(t *testing.T) (caFile, certFile, keyFile string, clientTLS *tls.Config) {
	t.Helper()
	tempDir := t.TempDir()

	// CA template
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(2025),
		Subject:               pkix.Name{Organization: []string{"Test CA"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 1, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	// CA private key
	caPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate CA private key: %v", err)
	}

	// Create self-signed CA certificate
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		t.Fatalf("Failed to create CA certificate: %v", err)
	}

	// PEM encode the CA cert
	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{Type: "CERTIFICATE", Bytes: caBytes})
	caFile = filepath.Join(tempDir, "ca.pem")
	if err := os.WriteFile(caFile, caPEM.Bytes(), 0600); err != nil {
		t.Fatalf("Failed to write CA file: %v", err)
	}

	// Server cert template
	serverCertTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2026),
		Subject:      pkix.Name{Organization: []string{"Test Server"}},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 1, 0),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	// Server private key
	serverPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate server private key: %v", err)
	}

	// Sign the server cert
	serverCertBytes, err := x509.CreateCertificate(rand.Reader, serverCertTmpl, ca, &serverPrivKey.PublicKey, caPrivKey)
	if err != nil {
		t.Fatalf("Failed to create server certificate: %v", err)
	}

	serverCertPEM := new(bytes.Buffer)
	pem.Encode(serverCertPEM, &pem.Block{Type: "CERTIFICATE", Bytes: serverCertBytes})
	certFile = filepath.Join(tempDir, "server.pem")
	if err := os.WriteFile(certFile, serverCertPEM.Bytes(), 0600); err != nil {
		t.Fatalf("Failed to write server cert file: %v", err)
	}

	serverPrivBytes, err := x509.MarshalPKCS8PrivateKey(serverPrivKey)
	if err != nil {
		t.Fatalf("Failed to marshal server private key: %v", err)
	}
	serverPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(serverPrivKeyPEM, &pem.Block{Type: "PRIVATE KEY", Bytes: serverPrivBytes})
	keyFile = filepath.Join(tempDir, "server-key.pem")
	if err := os.WriteFile(keyFile, serverPrivKeyPEM.Bytes(), 0600); err != nil {
		t.Fatalf("Failed to write server key file: %v", err)
	}

	// Client cert template
	clientCertTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2027),
		Subject:      pkix.Name{Organization: []string{"Test Client"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 1, 0),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	// Client private key
	clientPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate client private key: %v", err)
	}

	// Sign the client cert
	clientCertBytes, err := x509.CreateCertificate(rand.Reader, clientCertTmpl, ca, &clientPrivKey.PublicKey, caPrivKey)
	if err != nil {
		t.Fatalf("Failed to create client certificate: %v", err)
	}

	clientCertPEM := new(bytes.Buffer)
	pem.Encode(clientCertPEM, &pem.Block{Type: "CERTIFICATE", Bytes: clientCertBytes})

	clientPrivBytes, err := x509.MarshalPKCS8PrivateKey(clientPrivKey)
	if err != nil {
		t.Fatalf("Failed to marshal client private key: %v", err)
	}
	clientPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(clientPrivKeyPEM, &pem.Block{Type: "PRIVATE KEY", Bytes: clientPrivBytes})

	// Create the client's certificate object
	clientCert, err := tls.X509KeyPair(clientCertPEM.Bytes(), clientPrivKeyPEM.Bytes())
	if err != nil {
		t.Fatalf("Failed to create client key pair: %v", err)
	}

	// Client TLS config
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(caPEM.Bytes())
	clientTLS = &tls.Config{
		RootCAs:      certPool,
		Certificates: []tls.Certificate{clientCert},
	}

	return caFile, certFile, keyFile, clientTLS
}

// setupTest creates a server and client for integration tests.
func setupTest(t *testing.T, ctx context.Context) (*EtcdStore, *Client, func()) {
	t.Helper()

	port, err := getFreePort()
	if err != nil {
		t.Fatalf("Failed to get free port: %v", err)
	}
	listenURL := fmt.Sprintf("http://localhost:%d", port)
	t.Logf("Listening on %s", listenURL)

	// Setup server
	etcdDir := t.TempDir()
	server, err := NewEtcdStore(listenURL, etcdDir)
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}

	// Setup client
	dbPath := filepath.Join(t.TempDir(), "ipcache.bolt")
	boltStore, err := NewBoltStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create bolt store: %v", err)
	}
	lruStore := NewLRUStore(boltStore, 128)
	client, err := NewClient(context.Background(), listenURL, nil, lruStore, boltStore, "nodeA")
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	cleanup := func() {
		client.Close()
		server.Close()
		boltStore.Close()
	}

	return server, client, cleanup
}

// TestServerClientIntegration provides end-to-end coverage for the golden path.
func TestServerClientIntegration(t *testing.T) {
	// enable logging verbosity for debug tests
	// logs.GlogSetter("7")
	// Define the core test logic as a function to be reused.
	runTest := func(t *testing.T, useTLS bool) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		var server *EtcdStore
		var client *Client
		var cleanup func()

		// Setup based on whether TLS is used
		if useTLS {
			port, err := getFreePort()
			if err != nil {
				t.Fatalf("Failed to get free port: %v", err)
			}
			listenURL := fmt.Sprintf("https://localhost:%d", port)
			caFile, certFile, keyFile, clientTLSConfig := generateTestTLS(t)
			server, err = NewEtcdStore(listenURL, t.TempDir(), WithTLS(certFile, keyFile, caFile))
			if err != nil {
				t.Fatalf("Failed to start TLS server: %v", err)
			}

			dbPath := filepath.Join(t.TempDir(), "ipcache.bolt")
			boltStore, err := NewBoltStore(dbPath)
			if err != nil {
				t.Fatalf("Failed to create bolt store: %v", err)
			}
			lruStore := NewLRUStore(boltStore, 128)
			client, err = NewClient(ctx, listenURL, clientTLSConfig, lruStore, boltStore, "node")
			if err != nil {
				t.Fatalf("Failed to create TLS client: %v", err)
			}
			cleanup = func() {
				client.Close()
				server.Close()
				boltStore.Close()
			}
		} else {
			server, client, cleanup = setupTest(t, ctx)
		}
		defer cleanup()

		// 1. Test Get on non-existent key
		_, found := client.GetPodInfoByIP("1.2.3.4")
		if found {
			t.Fatal("Expected not to find non-existent record")
		}

		// 2. Test Upsert and Get
		podInfo1 := &api.PodInfo{Name: "pod1", Namespace: &api.Namespace{Name: "ns1"}}
		ip1 := "10.0.0.1"
		if err := server.Upsert(ip1, podInfo1); err != nil {
			t.Fatalf("Failed to upsert record: %v", err)
		}

		waitForCondition(t, "client did not sync upsert", func() bool {
			_, serverFound := server.GetPodInfoByIP(ip1)
			if !serverFound {
				t.Log("not found on server")
				return false
			}

			info, found := client.GetPodInfoByIP(ip1)
			if !found {
				t.Log("not found")
				return false
			}
			if info.Name == "pod1" {
				t.Log("found pod1")
				return true
			}
			t.Logf("found pod with name %s, expected pod1", info.Name)
			return false
		}, 5*time.Second)

		// 3. Test Update
		podInfo1v2 := &api.PodInfo{Name: "pod1-v2", Namespace: &api.Namespace{Name: "ns1"}}
		if err := server.Upsert(ip1, podInfo1v2); err != nil {
			t.Fatalf("Failed to update record: %v", err)
		}
		waitForCondition(t, "client did not sync update", func() bool {
			info, found := client.GetPodInfoByIP(ip1)
			return found && info.Name == "pod1-v2"
		}, 5*time.Second)

		// 4. Test List
		podInfo2 := &api.PodInfo{Name: "pod2", Namespace: &api.Namespace{Name: "ns2"}}
		ip2 := "10.0.0.2"
		if err := server.Upsert(ip2, podInfo2); err != nil {
			t.Fatalf("Failed to upsert record: %v", err)
		}
		waitForCondition(t, "client did not sync second upsert", func() bool {
			list, _ := client.List()
			if len(list) != 2 {
				return false
			}
			info, found := client.GetPodInfoByIP(ip2)
			return found && info.Name == "pod2"
		}, 5*time.Second)

		// 5. Test Delete
		if err := server.Delete(ip1); err != nil {
			t.Fatalf("Failed to delete record: %v", err)
		}
		waitForCondition(t, "client did not sync delete", func() bool {
			list, _ := client.List()
			if len(list) != 1 {
				return false
			}
			_, found := client.GetPodInfoByIP(ip1)
			return !found
		}, 10*time.Second)
		list, _ := client.List()
		if len(list) != 1 {
			t.Error("Expected 1 record remaining after delete")
		}
	}

	t.Run("Without TLS", func(t *testing.T) {
		runTest(t, false)
	})
	t.Run("With TLS", func(t *testing.T) {
		runTest(t, true)
	})
}

// TestClientRestart verifies a new client can resume from an existing database.
func TestClientRestart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server, client1, cleanup := setupTest(t, ctx)
	defer cleanup()
	dbPath := client1.syncStore.(*BoltStore).db.Path() // Get the path to the DB file

	// Upsert some data and wait for the first client to sync.
	podInfo1 := &api.PodInfo{Name: "pod1", Namespace: &api.Namespace{Name: "ns1"}}
	ip1 := "10.0.0.1"
	if err := server.Upsert(ip1, podInfo1); err != nil {
		t.Fatalf("Failed to upsert record: %v", err)
	}
	waitForCondition(t, "client did not sync upsert", func() bool {
		info, found := client1.GetPodInfoByIP(ip1)
		return found && info.Name == "pod1"
	}, 5*time.Second)

	// Close the first client, but leave the server running.
	client1.Close()

	// Create a new client with the same db path.
	boltStore, err := NewBoltStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create bolt store: %v", err)
	}
	lruStore := NewLRUStore(boltStore, 128)
	client2, err := NewClient(context.Background(), server.listenURL, nil, lruStore, boltStore, "nodeA")
	if err != nil {
		t.Fatalf("Failed to create second client: %v", err)
	}
	defer client2.Close()

	// The new client should have the data from its local DB immediately.
	info, found := client2.GetPodInfoByIP(ip1)
	if !found {
		t.Fatal("Expected to find record in new client, but did not")
	}
	if info.Name != "pod1" {
		t.Errorf("Expected pod name 'pod1', got '%s'", info.Name)
	}

	// Upsert new data and verify the new client syncs it.
	podInfo2 := &api.PodInfo{Name: "pod2", Namespace: &api.Namespace{Name: "ns2"}}
	ip2 := "10.0.0.2"
	if err := server.Upsert(ip2, podInfo2); err != nil {
		t.Fatalf("Failed to upsert second record: %v", err)
	}

	waitForCondition(t, "second client did not sync new upsert", func() bool {
		info, found := client2.GetPodInfoByIP(ip2)
		return found && info.Name == "pod2"
	}, 5*time.Second)
}

// TestFullSyncOnServerRestart verifies the client performs a full sync when the server it
// connects to is different from the one it was last synced with.
func TestFullSyncOnServerRestart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// --- Phase 1: Start server1, connect client, sync data, and shut down client ---
	dbPath := filepath.Join(t.TempDir(), "ipcache.bolt")

	server1, client1, cleanup1 := setupTest(t, ctx)

	ip := "10.0.0.1"
	podInfo := &api.PodInfo{Name: "pod1", Namespace: &api.Namespace{Name: "ns1"}}
	if err := server1.Upsert(ip, podInfo); err != nil {
		t.Fatalf("Upsert failed: %v", err)
	}

	waitForCondition(t, "client1 did not sync upsert", func() bool {
		info, found := client1.GetPodInfoByIP(ip)
		return found && info.Name == "pod1"
	}, 5*time.Second)

	cleanup1()

	// --- Phase 2: Start a new, empty server2 ---
	port2, err := getFreePort()
	if err != nil {
		t.Fatalf("Failed to get free port for server2: %v", err)
	}
	listenURL2 := fmt.Sprintf("http://localhost:%d", port2)
	etcdDir2 := t.TempDir()
	server2, err := NewEtcdStore(listenURL2, etcdDir2)
	if err != nil {
		t.Fatalf("Failed to start server2: %v", err)
	}
	defer server2.Close()

	// --- Phase 3: Start a new client pointing to server2 but using the old DB ---
	boltStore, err := NewBoltStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create bolt store: %v", err)
	}
	lruStore := NewLRUStore(boltStore, 128)
	client2, err := NewClient(context.Background(), listenURL2, nil, lruStore, boltStore, "nodeA")
	if err != nil {
		t.Fatalf("Failed to create client2: %v", err)
	}
	defer client2.Close()

	// The client should detect that the server's cluster/member ID is different
	// from what's in its DB, trigger a full sync, and wipe its local data
	// because the new server is empty.
	waitForCondition(t, "client2 did not re-sync to an empty state", func() bool {
		// The LRU cache should be empty, and BoltDB should also be empty.
		list, _ := client2.List()
		return len(list) == 0
	}, 10*time.Second)
}

// TestStress performs many concurrent operations to test for race conditions and performance.
func TestStress(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server, _, cleanup := setupTest(t, ctx)
	defer cleanup()
	listenURL := server.listenURL

	const (
		initialIPs = 1000
		totalIPs   = 2000
		deletedIPs = totalIPs / 2
		numClients = 5
	)

	ips := make(map[string][]net.IP)
	ips[testClusterID] = make([]net.IP, totalIPs)
	ips[testClusterID2] = make([]net.IP, totalIPs)

	prefix := net.ParseIP("2001:db8:cafe::").To16()

	for i := 0; i < totalIPs; i++ {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, uint32(i))
		ips[testClusterID][i] = ip

		ip2 := make(net.IP, 16)
		copy(ip2, prefix)
		binary.BigEndian.PutUint32(ip2[12:16], uint32(i+totalIPs))
		ips[testClusterID2][i] = ip2
	}

	// Add initial IPs for both clusters
	for i := 0; i < initialIPs; i++ {
		podInfo := &api.PodInfo{Name: "pod-" + strconv.Itoa(i), Namespace: &api.Namespace{Name: "ns"}}
		if err := server.Upsert(ips[testClusterID][i].String(), podInfo); err != nil {
			t.Fatalf("Failed to upsert record: %v", err)
		}
		if err := server.Upsert(ips[testClusterID2][i].String(), podInfo); err != nil {
			t.Fatalf("Failed to upsert record: %v", err)
		}
	}

	// Create clients
	clients := make([]*Client, numClients)
	for i := 0; i < numClients; i++ {
		dbDir := filepath.Join(t.TempDir(), fmt.Sprintf("ipcache%d.bolt", i))
		boltStore, err := NewBoltStore(dbDir)
		if err != nil {
			t.Fatalf("Failed to create bolt store: %v", err)
		}
		lruStore := NewLRUStore(boltStore, totalIPs*2)
		client, err := NewClient(context.Background(), listenURL, nil, lruStore, boltStore, "nodeA")
		if err != nil {
			t.Fatalf("Failed to create client %d: %v", i, err)
		}
		defer client.Close()
		clients[i] = client
	}

	// Check initial sync
	for i, client := range clients {
		waitForCondition(t, fmt.Sprintf("client %d did not sync initial records", i), func() bool {
			_, found := client.GetPodInfoByIP(ips[testClusterID][0].String())
			if !found {
				return false
			}
			_, found = client.GetPodInfoByIP(ips[testClusterID2][0].String())
			if !found {
				return false
			}
			list, err := client.List()
			if err != nil {
				t.Errorf("client %d failed to list records: %v", i, err)
				return false
			}
			return len(list) == initialIPs*2
		}, 30*time.Second)
	}

	// Add remaining IPs concurrently
	var wg sync.WaitGroup
	for i := initialIPs; i < totalIPs; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			podInfo := &api.PodInfo{Name: "pod-" + strconv.Itoa(i), Namespace: &api.Namespace{Name: "ns"}}
			if err := server.Upsert(ips[testClusterID][i].String(), podInfo); err != nil {
				// Use t.Error for goroutines to avoid immediate test failure
				t.Errorf("Failed to upsert record: %v", err)
			}
			if err := server.Upsert(ips[testClusterID2][i].String(), podInfo); err != nil {
				t.Errorf("Failed to upsert record: %v", err)
			}
		}(i)
	}
	wg.Wait()

	// Check all clients have synced the additions
	for i, client := range clients {
		waitForCondition(t, fmt.Sprintf("client %d did not sync all records", i), func() bool {
			_, found := client.GetPodInfoByIP(ips[testClusterID][0].String())
			if !found {
				return false
			}
			_, found = client.GetPodInfoByIP(ips[testClusterID2][0].String())
			if !found {
				return false
			}
			list, err := client.List()
			if err != nil {
				t.Errorf("client %d failed to list records: %v", i, err)
				return false
			}
			return len(list) == totalIPs*2
		}, 30*time.Second)
	}

	// Delete K IPs from both clusters concurrently
	for i := 0; i < deletedIPs; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := server.Delete(ips[testClusterID][i].String()); err != nil {
				t.Errorf("Failed to delete record: %v", err)
			}
			if err := server.Delete(ips[testClusterID2][i].String()); err != nil {
				t.Errorf("Failed to delete record: %v", err)
			}
		}(i)
	}
	wg.Wait()

	// Check all clients have synced the deletions
	for i, client := range clients {
		waitForCondition(t, fmt.Sprintf("client %d did not sync deletions", i), func() bool {
			_, found := client.GetPodInfoByIP(ips[testClusterID][0].String())
			if found {
				return false
			}
			_, found = client.GetPodInfoByIP(ips[testClusterID2][0].String())
			if found {
				return false
			}
			list, err := client.List()
			if err != nil {
				t.Errorf("client %d failed to list records: %v", i, err)
				return false
			}
			return len(list) == (totalIPs-deletedIPs)*2
		}, 30*time.Second)
	}
}

// TestNewClientFailsOnBadEndpoint verifies that NewClient returns an error
// immediately if it cannot connect to the server.
func TestNewClientFailsOnBadEndpoint(t *testing.T) {
	// Get a free port but don't start a server on it.
	port, err := getFreePort()
	if err != nil {
		t.Fatalf("Failed to get free port: %v", err)
	}
	listenURL := fmt.Sprintf("localhost:%d", port)
	dbPath := filepath.Join(t.TempDir(), "ipcache.bolt")
	boltStore, err := NewBoltStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create bolt store: %v", err)
	}
	lruStore := NewLRUStore(boltStore, 128)

	_, err = NewClient(context.Background(), listenURL, nil, lruStore, boltStore, "nodeA")
	if err == nil {
		t.Fatal("Expected NewClient to fail with a bad endpoint, but it succeeded")
	}
}

// TestServerProxyClientIntegration tests the Server <-> CacheProxy <-> Client scenario.
func TestServerProxyClientIntegration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 1. Setup the main server
	server, _, cleanup := setupTest(t, ctx)
	defer cleanup()

	// 2. Setup the cache proxy
	proxyPort, err := getFreePort()
	if err != nil {
		t.Fatalf("Failed to get free port for proxy: %v", err)
	}
	proxyListenURL := fmt.Sprintf("http://localhost:%d", proxyPort)
	proxyEtcdDir := t.TempDir()
	proxyStore, err := NewEtcdStore(proxyListenURL, proxyEtcdDir)
	if err != nil {
		t.Fatalf("Failed to start proxy store: %v", err)
	}
	defer proxyStore.Close()

	proxyClient, err := NewClient(ctx, server.listenURL, nil, proxyStore, proxyStore, "nodeA")
	if err != nil {
		t.Fatalf("Failed to create proxy client: %v", err)
	}
	defer proxyClient.Close()

	// 3. Setup the final client
	finalDbPath := filepath.Join(t.TempDir(), "ipcache.bolt")
	finalBoltStore, err := NewBoltStore(finalDbPath)
	if err != nil {
		t.Fatalf("Failed to create final bolt store: %v", err)
	}
	finalLruStore := NewLRUStore(finalBoltStore, 128)
	finalClient, err := NewClient(ctx, proxyListenURL, nil, finalLruStore, finalBoltStore, "nodeA")
	if err != nil {
		t.Fatalf("Failed to create final client: %v", err)
	}
	defer finalClient.Close()

	// 5. Test data propagation
	podInfo1 := &api.PodInfo{Name: "pod1", Namespace: &api.Namespace{Name: "ns1"}}
	ip1 := "10.0.0.1"
	if err := server.Upsert(ip1, podInfo1); err != nil {
		t.Fatalf("Failed to upsert record: %v", err)
	}

	waitForCondition(t, "proxy client did not sync upsert", func() bool {
		info, found := proxyClient.GetPodInfoByIP(ip1)
		return found && info.Name == "pod1"
	}, 15*time.Second)

	waitForCondition(t, "final client did not sync upsert", func() bool {
		info, found := finalClient.GetPodInfoByIP(ip1)
		return found && info.Name == "pod1"
	}, 15*time.Second)

	// 6. Test Update
	podInfo1v2 := &api.PodInfo{Name: "pod1-v2", Namespace: &api.Namespace{Name: "ns1"}}
	if err := server.Upsert(ip1, podInfo1v2); err != nil {
		t.Fatalf("Failed to update record: %v", err)
	}
	waitForCondition(t, "proxy client did not sync update", func() bool {
		info, found := proxyClient.GetPodInfoByIP(ip1)
		return found && info.Name == "pod1-v2"
	}, 15*time.Second)
	waitForCondition(t, "final client did not sync update", func() bool {
		info, found := finalClient.GetPodInfoByIP(ip1)
		return found && info.Name == "pod1-v2"
	}, 15*time.Second)

	// 7. Test Delete
	if err := server.Delete(ip1); err != nil {
		t.Fatalf("Failed to delete record: %v", err)
	}
	waitForCondition(t, "proxy client did not sync delete", func() bool {
		_, found := proxyClient.GetPodInfoByIP(ip1)
		return !found
	}, 15*time.Second)
	waitForCondition(t, "final client did not sync delete", func() bool {
		_, found := finalClient.GetPodInfoByIP(ip1)
		return !found
	}, 15*time.Second)
}

// Helper to calculate the size of a directory
func dirSize(path string) (int64, error) {
	var size int64
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return err
	})
	return size, err
}

// TestScalability measures propagation delay, memory, and disk usage.
func TestScalability(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}
	const (
		numClients          = 1
		numNamespaces       = 10
		numPodsPerNamespace = 1000000
		totalPods           = numNamespaces * numPodsPerNamespace
		qps                 = 1024
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.Log("Setting up server")
	server, _, cleanup := setupTest(t, ctx)
	defer cleanup()
	listenURL := server.listenURL

	t.Log("Setting up clients")
	clients := make([]*Client, numClients)
	for i := 0; i < numClients; i++ {
		dbDir := filepath.Join(t.TempDir(), fmt.Sprintf("ipcache%d.bolt", i))
		boltStore, err := NewBoltStore(dbDir)
		if err != nil {
			t.Fatalf("Failed to create bolt store: %v", err)
		}
		lruStore := NewLRUStore(boltStore, totalPods*2)
		client, err := NewClient(context.Background(), listenURL, nil, lruStore, boltStore, fmt.Sprintf("node-%d", i))
		if err != nil {
			t.Fatalf("Failed to create client %d: %v", i, err)
		}
		defer client.Close()
		clients[i] = client
	}

	t.Log("Create namespaces and pods")
	ips := make([]string, totalPods)
	podInfos := make([]*api.PodInfo, totalPods)
	for i := 0; i < numNamespaces; i++ {
		ns := fmt.Sprintf("ns%d", i)
		for j := 0; j < numPodsPerNamespace; j++ {
			podIndex := i*numPodsPerNamespace + j
			podName := fmt.Sprintf("pod-%d", podIndex)
			ip := make(net.IP, 4)
			binary.BigEndian.PutUint32(ip, uint32(podIndex))
			ips[podIndex] = ip.String()
			podInfos[podIndex] = &api.PodInfo{Name: podName,
				Labels: map[string]string{"foo": "bar"},
				Namespace: &api.Namespace{
					Name:   ns,
					Labels: map[string]string{"foo": "bar"},
				},
			}
		}
	}

	t.Log("Measure initial state")
	var beforeMemStats runtime.MemStats
	runtime.ReadMemStats(&beforeMemStats)
	serverDirSize, err := dirSize(server.etcd.Config().Dir)
	if err != nil {
		t.Fatalf("Failed to get server dir size: %v", err)
	}
	t.Logf("Initial server disk usage: %.2f KB", float64(serverDirSize)/1024)

	// 5. Upsert all pods and measure propagation delay
	var totalPropagationDelay time.Duration
	var propagationDelayCount int64
	var mu sync.Mutex
	var wg sync.WaitGroup
	rateLimiter := rate.NewLimiter(rate.Limit(qps), 1)
	t.Log("Insert all pods")

	for i := 0; i < totalPods; i++ {
		err := rateLimiter.WaitN(ctx, 1)
		if err != nil {
			t.Logf("Rate limiter error: %v", err)
			continue
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			startTime := time.Now()
			if err := server.Upsert(ips[i], podInfos[i]); err != nil {
				t.Errorf("Failed to upsert record: %v", err)
				return
			}

			// Wait for the first client to receive the update
			waitForCondition(t, "client did not sync upsert", func() bool {
				_, found := clients[0].GetPodInfoByIP(ips[i])
				return found
			}, 10*time.Second)

			mu.Lock()
			totalPropagationDelay += time.Since(startTime)
			propagationDelayCount++
			mu.Unlock()
			t.Logf("Inserted pod %d", i)
		}(i)
	}
	wg.Wait()

	t.Log("Wait for all clients to sync")
	for i, client := range clients {
		waitForCondition(t, fmt.Sprintf("client %d did not sync all records", i), func() bool {
			list, err := client.List()
			if err != nil {
				t.Errorf("client %d failed to list records: %v", i, err)
				return false
			}
			t.Logf("Synced %d records", len(list))
			return len(list) == totalPods
		}, 30*time.Second)
	}

	// 7. Measure final state
	var afterMemStats runtime.MemStats
	runtime.ReadMemStats(&afterMemStats)

	t.Logf("--- Scalability Metrics ---")
	t.Logf("Number of clients: %d", numClients)
	t.Logf("Number of namespaces: %d", numNamespaces)
	t.Logf("Number of pods: %d", totalPods)
	t.Logf("Write QPS: %d", qps)

	if propagationDelayCount > 0 {
		avgPropagationDelay := totalPropagationDelay / time.Duration(propagationDelayCount)
		t.Logf("Average propagation delay: %s", avgPropagationDelay)
	}

	// Server metrics
	serverDirSizeAfter, err := dirSize(server.etcd.Config().Dir)
	if err != nil {
		t.Fatalf("Failed to get server dir size: %v", err)
	}
	t.Logf("Server memory usage (Alloc): %.2f KB", float64(afterMemStats.Alloc-beforeMemStats.Alloc)/1024)
	t.Logf("Server disk usage difference: %.2f KB", float64(serverDirSizeAfter-serverDirSize)/1024)

	// Client metrics
	for i, client := range clients {
		clientDbPath := client.syncStore.(*BoltStore).db.Path()
		clientDbSize, err := os.Stat(clientDbPath)
		if err != nil {
			t.Fatalf("Failed to get client db size: %v", err)
		}
		t.Logf("Client %d disk usage (BoltDB): %.2f KB", i, float64(clientDbSize.Size())/1024)
	}
}
