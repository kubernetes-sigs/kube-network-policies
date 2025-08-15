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
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/testing/protocmp"
	"sigs.k8s.io/kube-network-policies/pkg/api"
)

func newTestBoltStore(t *testing.T) *BoltStore {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	store, err := NewBoltStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create test bolt store: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func TestBoltStore_Store(t *testing.T) {
	store := newTestBoltStore(t)

	podInfo1 := &api.PodInfo{Name: "pod1"}
	podInfo2 := &api.PodInfo{Name: "pod2"}

	tests := []struct {
		name    string
		ip      string
		podInfo *api.PodInfo
	}{
		{
			name:    "pod1",
			ip:      "192.168.1.1",
			podInfo: podInfo1,
		},
		{
			name:    "pod2",
			ip:      "192.168.1.2",
			podInfo: podInfo2,
		},
	}

	// Test Upsert and Get
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := store.Upsert(tt.ip, tt.podInfo)
			if err != nil {
				t.Fatalf("Upsert() error = %v", err)
			}

			got, found := store.GetPodInfoByIP(tt.ip)
			if !found {
				t.Fatalf("GetPodInfoByIP() not found for ip %s", tt.ip)
			}
			if diff := cmp.Diff(tt.podInfo, got, protocmp.Transform()); diff != "" {
				t.Errorf("GetPodInfoByIP() mismatch (-want +got):\n%s", diff)
			}
		})
	}

	// Test List
	list, err := store.List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(list) != 2 {
		t.Errorf("len(List()) = %d; want 2", len(list))
	}

	// Test Delete
	err = store.Delete("192.168.1.1")
	if err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	// Verify deletion
	_, found := store.GetPodInfoByIP("192.168.1.1")
	if found {
		t.Error("item found after deletion")
	}

	// Verify that the other item still exists
	_, found = store.GetPodInfoByIP("192.168.1.2")
	if !found {
		t.Error("item not found after deleting another item")
	}
}

func TestBoltStore_SyncMetadata(t *testing.T) {
	store := newTestBoltStore(t)

	metadata := &SyncMetadata{
		Revision:  12345,
		ClusterID: 67890,
		MemberID:  54321,
	}

	err := store.SetSyncMetadata(metadata)
	if err != nil {
		t.Fatalf("SetSyncMetadata() error = %v", err)
	}

	got, err := store.GetSyncMetadata()
	if err != nil {
		t.Fatalf("GetSyncMetadata() error = %v", err)
	}

	if diff := cmp.Diff(metadata, got); diff != "" {
		t.Errorf("GetSyncMetadata() mismatch (-want +got):\n%s", diff)
	}
}
