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
	"errors"
	"sync"

	"k8s.io/klog/v2"
	"k8s.io/utils/lru"
	"sigs.k8s.io/kube-network-policies/pkg/api"
)

// LRUStore is a decorator for a Store that adds an in-memory LRU cache.
// It ensures that the LRU cache is kept consistent with the underlying store
// for operations passing through it.
type LRUStore struct {
	mu    sync.Mutex
	lru   *lru.Cache
	store Store
}

var _ Store = &LRUStore{}
var _ api.PodInfoProvider = &LRUStore{}

// NewLRUStore creates a new LRUStore.
// Size 0 means no limit.
func NewLRUStore(store Store, size int) *LRUStore {
	return &LRUStore{
		lru:   lru.New(size),
		store: store,
	}
}

// Get first checks the LRU cache. If the item is not found, it falls back
// to the underlying store and adds the item to the LRU cache for future lookups.
func (s *LRUStore) GetPodInfoByIP(ip string) (*api.PodInfo, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	klog.V(7).Infof("Get LRU(%s)", ip)
	if val, ok := s.lru.Get(ip); ok {
		return val.(*api.PodInfo), true
	}
	if s.store != nil {
		klog.V(7).Infof("Get Store(%s)", ip)
		info, found := s.store.GetPodInfoByIP(ip)
		if found {
			s.lru.Add(ip, info)
		}
		return info, found
	}

	return nil, false
}

// Upsert adds/updates the item in the LRU cache and then passes the operation
// to the underlying store.
func (s *LRUStore) Upsert(ip string, info *api.PodInfo) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	klog.V(7).Infof("Upsert LRU(%s)", ip)
	s.lru.Add(ip, info)
	if s.store != nil {
		klog.V(7).Infof("Upsert Store(%s)", ip)
		return s.store.Upsert(ip, info)
	}
	return nil
}

// Delete removes the item from the LRU cache and then passes the operation
// to the underlying store.
func (s *LRUStore) Delete(ip string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	klog.V(7).Infof("Delete LRU(%s)", ip)
	s.lru.Remove(ip)
	if s.store != nil {
		klog.V(7).Infof("Delete Store(%s)", ip)
		return s.store.Delete(ip)
	}
	return nil

}

// List returns all items from the underlying store.
// Note: This operation does not interact with the LRU cache and will
// return an error if the store is not configured.
func (s *LRUStore) List() ([]*api.PodInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.store != nil {
		return s.store.List()
	}
	// The LRU cache itself does not support listing all items.
	return nil, errors.New("List operation is not supported for in-memory-only cache")
}

// Clear removes all items from the underlying store and the LRU cache.
func (s *LRUStore) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lru.Clear() // Clear the LRU cache
	if s.store != nil {
		return s.store.Clear()
	}
	return nil
}

// Close closes the underlying store, if it exists.
func (s *LRUStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.store != nil {
		return s.store.Close()
	}
	return nil
}
