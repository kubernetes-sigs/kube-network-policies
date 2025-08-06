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
	"os"
	"path/filepath"
	"testing"
	"time"
)

const testClusterID = "test-cluster"

// Helper to wait for a condition to be true or fail after a timeout.
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

func TestServerClientIntegration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup server
	etcdDir := filepath.Join(t.TempDir(), "ipcache.etcd")
	if err := os.MkdirAll(etcdDir, 0700); err != nil {
		t.Fatalf("failed to create etcd dir: %v", err)
	}
	server, err := NewServer("http://localhost:9090", etcdDir)
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer server.Close()

	// Setup client
	dbDir := filepath.Join(t.TempDir(), "ipcache.bolt")
	client, err := NewClient(ctx, "http://localhost:9090", dbDir)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	// 1. Test Upsert
	podInfo1 := &PodInfo{PodName: "pod1", PodNamespace: "ns1"}
	ip1 := "10.0.0.1"
	if err := server.Upsert(ctx, testClusterID, ip1, podInfo1); err != nil {
		t.Fatalf("Failed to upsert record: %v", err)
	}

	// Wait for client to sync
	waitForCondition(t, "client did not sync upsert", func() bool {
		info, found := client.Get(testClusterID, ip1)
		return found && info.PodName == "pod1"
	}, 2*time.Second)

	// 2. Test Get
	info, found := client.Get(testClusterID, ip1)
	if !found {
		t.Fatal("Expected to find record, but did not")
	}
	if info.PodName != "pod1" {
		t.Errorf("Expected pod name 'pod1', got '%s'", info.PodName)
	}

	// 3. Test List
	records := client.List()
	if len(records) != 1 {
		t.Fatalf("Expected 1 record, got %d", len(records))
	}
	if records[0].PodName != "pod1" {
		t.Errorf("Expected pod name 'pod1' in list, got '%s'", records[0].PodName)
	}

	// 4. Test Delete
	if err := server.Delete(ctx, testClusterID, ip1); err != nil {
		t.Fatalf("Failed to delete record: %v", err)
	}

	// Wait for client to sync delete
	waitForCondition(t, "client did not sync delete", func() bool {
		_, found := client.Get(testClusterID, ip1)
		return !found
	}, 2*time.Second)

	// Verify it's gone
	_, found = client.Get(testClusterID, ip1)
	if found {
		t.Fatal("Expected record to be deleted, but it was found")
	}
}
