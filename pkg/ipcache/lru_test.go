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
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/testing/protocmp"
	"sigs.k8s.io/kube-network-policies/pkg/api"
)

func TestLRUStore(t *testing.T) {
	store := NewLocalIPCache()
	lruStore := NewLRUStore(store, 2)

	podInfo1 := &api.PodInfo{Name: "pod1"}
	podInfo2 := &api.PodInfo{Name: "pod2"}
	podInfo3 := &api.PodInfo{Name: "pod3"}

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
		{
			name:    "pod3",
			ip:      "192.168.1.3",
			podInfo: podInfo3,
		},
	}

	// Test Upsert and Get
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := lruStore.Upsert(tt.ip, tt.podInfo)
			if err != nil {
				t.Fatalf("Upsert() error = %v", err)
			}

			// Verify that the item is in the LRU cache
			got, found := lruStore.lru.Get(tt.ip)
			if !found {
				t.Fatalf("item not found in LRU cache for ip %s", tt.ip)
			}
			if diff := cmp.Diff(tt.podInfo, got.(*api.PodInfo), protocmp.Transform()); diff != "" {
				t.Errorf("LRU cache mismatch (-want +got):\n%s", diff)
			}

			// Verify that the item is in the underlying store
			got, found = store.GetPodInfoByIP(tt.ip)
			if !found {
				t.Fatalf("item not found in store for ip %s", tt.ip)
			}
			if diff := cmp.Diff(tt.podInfo, got, protocmp.Transform()); diff != "" {
				t.Errorf("store mismatch (-want +got):\n%s", diff)
			}
		})
	}

	// Test LRU eviction
	_, found := lruStore.lru.Get("192.168.1.1")
	if found {
		t.Error("expected item to be evicted from LRU cache")
	}

	// Test Delete
	err := lruStore.Delete("192.168.1.2")
	if err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	// Verify that the item is not in the LRU cache
	_, found = lruStore.lru.Get("192.168.1.2")
	if found {
		t.Error("item found in LRU cache after deletion")
	}

	// Verify that the item is not in the underlying store
	_, found = store.GetPodInfoByIP("192.168.1.2")
	if found {
		t.Error("item found in store after deletion")
	}

	// Test List
	list, err := lruStore.List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(list) != 2 {
		t.Errorf("len(List()) = %d; want 2", len(list))
	}

	// Test List with no store
	lruStoreNoStore := NewLRUStore(nil, 2)
	_, err = lruStoreNoStore.List()
	if err == nil {
		t.Errorf("List() with no store should return an error")
	}
}
