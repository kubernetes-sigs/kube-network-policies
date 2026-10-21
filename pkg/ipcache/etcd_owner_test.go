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
	"sync"
	"testing"

	"sigs.k8s.io/kube-network-policies/pkg/api"
)

func ownerPodInfo(name, uid string) *api.PodInfo {
	return &api.PodInfo{Name: name, Namespace: &api.Namespace{Name: "ns1"}, Uid: uid}
}

// entryOwner returns "namespace/name uid" of the entry of the IP, or "" if none.
func entryOwner(t *testing.T, store *EtcdStore, ip string) string {
	t.Helper()
	info, ok := store.GetPodInfoByIP(ip)
	if !ok {
		return ""
	}
	return info.GetNamespace().GetName() + "/" + info.GetName() + " " + info.GetUid()
}

func TestEtcdStore_DeleteIfOwner(t *testing.T) {
	store := newTestEtcdStore(t)

	tests := []struct {
		name   string
		stored *api.PodInfo
		owner  *api.PodInfo
		want   string
	}{
		{
			name:   "entry of the pod",
			stored: ownerPodInfo("pod-a", "uid-a"),
			owner:  ownerPodInfo("pod-a", "uid-a"),
			want:   "",
		},
		{
			name:   "entry of another pod",
			stored: ownerPodInfo("pod-b", "uid-b"),
			owner:  ownerPodInfo("pod-a", "uid-a"),
			want:   "ns1/pod-b uid-b",
		},
		{
			name:   "entry of another pod with the same name",
			stored: ownerPodInfo("web-0", "uid-b"),
			owner:  ownerPodInfo("web-0", "uid-a"),
			want:   "ns1/web-0 uid-b",
		},
		{
			name:   "entry without UID of the pod",
			stored: ownerPodInfo("pod-a", ""),
			owner:  ownerPodInfo("pod-a", "uid-a"),
			want:   "",
		},
		{
			name:   "entry without UID of another pod",
			stored: ownerPodInfo("pod-b", ""),
			owner:  ownerPodInfo("pod-a", "uid-a"),
			want:   "ns1/pod-b ",
		},
		{
			name:   "owner without UID",
			stored: ownerPodInfo("pod-a", "uid-a"),
			owner:  ownerPodInfo("pod-a", ""),
			want:   "",
		},
	}
	for _, tt := range tests {
		for _, ip := range []string{"10.0.0.1", "fd00::1"} {
			t.Run(tt.name+"/"+ip, func(t *testing.T) {
				if err := store.Upsert(ip, tt.stored); err != nil {
					t.Fatalf("Upsert() failed: %v", err)
				}

				if err := store.DeleteIfOwner(ip, tt.owner); err != nil {
					t.Fatalf("DeleteIfOwner() failed: %v", err)
				}

				if got := entryOwner(t, store, ip); got != tt.want {
					t.Errorf("entry of %s = %q, want %q", ip, got, tt.want)
				}
				_ = store.Delete(ip)
			})
		}
	}

	t.Run("no entry", func(t *testing.T) {
		if err := store.DeleteIfOwner("10.0.0.9", ownerPodInfo("pod-a", "uid-a")); err != nil {
			t.Errorf("DeleteIfOwner() failed: %v", err)
		}
	})

	t.Run("invalid IP", func(t *testing.T) {
		if err := store.DeleteIfOwner("not-an-ip", ownerPodInfo("pod-a", "uid-a")); err == nil {
			t.Error("DeleteIfOwner() succeeded, want an error")
		}
	})
}

func TestEtcdStore_DeleteIfOwnerStorageError(t *testing.T) {
	store := newTestEtcdStore(t)
	if err := store.Upsert("10.0.0.1", ownerPodInfo("pod-a", "uid-a")); err != nil {
		t.Fatalf("Upsert() failed: %v", err)
	}
	store.Close()

	if err := store.DeleteIfOwner("10.0.0.1", ownerPodInfo("pod-a", "uid-a")); err == nil {
		t.Error("DeleteIfOwner() on a closed store succeeded, want an error")
	}
}

// The entry is deleted only if it was not modified after it was read, an
// Upsert in between keeps the new entry.
func TestEtcdStore_DeleteIfUnchanged(t *testing.T) {
	store := newTestEtcdStore(t)
	ctx := context.Background()

	for _, ip := range []string{"10.0.0.1", "fd00::1"} {
		t.Run(ip, func(t *testing.T) {
			key, err := ipToKey(ip)
			if err != nil {
				t.Fatalf("ipToKey() failed: %v", err)
			}
			if err := store.Upsert(ip, ownerPodInfo("pod-a", "uid-a")); err != nil {
				t.Fatalf("Upsert() failed: %v", err)
			}
			resp, err := store.client.Get(ctx, key)
			if err != nil || len(resp.Kvs) != 1 {
				t.Fatalf("Get() = %v, %v; want the entry of pod-a", resp, err)
			}
			readRevision := resp.Kvs[0].ModRevision

			// pod-b gets the IP after the entry of pod-a was read.
			if err := store.Upsert(ip, ownerPodInfo("pod-b", "uid-b")); err != nil {
				t.Fatalf("Upsert() failed: %v", err)
			}
			deleted, err := store.deleteIfUnchanged(ctx, key, readRevision)
			if err != nil || deleted {
				t.Errorf("deleteIfUnchanged() = %v, %v; want false, nil", deleted, err)
			}
			if got := entryOwner(t, store, ip); got != "ns1/pod-b uid-b" {
				t.Errorf("entry of %s = %q, want %q", ip, got, "ns1/pod-b uid-b")
			}

			// The entry is deleted if it did not change.
			resp, err = store.client.Get(ctx, key)
			if err != nil || len(resp.Kvs) != 1 {
				t.Fatalf("Get() = %v, %v; want the entry of pod-b", resp, err)
			}
			deleted, err = store.deleteIfUnchanged(ctx, key, resp.Kvs[0].ModRevision)
			if err != nil || !deleted {
				t.Errorf("deleteIfUnchanged() = %v, %v; want true, nil", deleted, err)
			}
			if got := entryOwner(t, store, ip); got != "" {
				t.Errorf("entry of %s = %q, want none", ip, got)
			}
		})
	}
}

// Whatever the order of the Upsert of the new owner and the delete for the
// previous owner, the entry of the new owner is kept.
func TestEtcdStore_DeleteIfOwnerConcurrentUpsert(t *testing.T) {
	store := newTestEtcdStore(t)
	for i := range 50 {
		ip := "10.0.0.1"
		if i%2 == 1 {
			ip = "fd00::1"
		}
		if err := store.Upsert(ip, ownerPodInfo("pod-a", "uid-a")); err != nil {
			t.Fatalf("Upsert() failed: %v", err)
		}

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			if err := store.Upsert(ip, ownerPodInfo("pod-b", "uid-b")); err != nil {
				t.Errorf("Upsert() failed: %v", err)
			}
		}()
		go func() {
			defer wg.Done()
			if err := store.DeleteIfOwner(ip, ownerPodInfo("pod-a", "uid-a")); err != nil {
				t.Errorf("DeleteIfOwner() failed: %v", err)
			}
		}()
		wg.Wait()

		if got := entryOwner(t, store, ip); got != "ns1/pod-b uid-b" {
			t.Fatalf("iteration %d: entry of %s = %q, want %q", i, ip, got, "ns1/pod-b uid-b")
		}
	}
}
