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
	"sync"
	"time"

	"k8s.io/utils/lru"
	"sigs.k8s.io/kube-network-policies/pkg/api"
)

type posEntry struct {
	podInfo   *api.PodInfo // treated as immutable; never mutated by callers
	expiresAt time.Time
}

// ReaderCache holds separate bounded TTL/LRU caches for positive PodInfo hits
// and negative misses so external-IP scans cannot evict warm pod entries.
// Stored *api.PodInfo pointers are immutable, avoiding proto.Clone under lock.
type ReaderCache struct {
	mu  sync.Mutex
	pos *lru.Cache
	neg *lru.Cache
}

// NewReaderCache creates a ReaderCache with capacity size for positive entries
// and size for negative entries (0 means unbounded).
func NewReaderCache(size int) *ReaderCache {
	return &ReaderCache{
		pos: lru.New(size),
		neg: lru.New(size),
	}
}

// Get checks the positive cache first and then the negative cache at time now.
func (c *ReaderCache) Get(ip string, now time.Time) (info *api.PodInfo, found bool, hit bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if val, ok := c.pos.Get(ip); ok {
		entry := val.(*posEntry)
		if entry.expiresAt.After(now) {
			return entry.podInfo, true, true
		}
		c.pos.Remove(ip)
	}
	if val, ok := c.neg.Get(ip); ok {
		exp := val.(time.Time)
		if exp.After(now) {
			return nil, false, true
		}
		c.neg.Remove(ip)
	}
	return nil, false, false
}

// SetPositive stores an immutable PodInfo for ip with the given TTL.
func (c *ReaderCache) SetPositive(ip string, info *api.PodInfo, ttl time.Duration, now time.Time) {
	if ttl <= 0 || info == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.neg.Remove(ip)
	c.pos.Add(ip, &posEntry{
		podInfo:   info,
		expiresAt: now.Add(ttl),
	})
}

// SetNegative records a definitive miss for ip with the given TTL.
func (c *ReaderCache) SetNegative(ip string, ttl time.Duration, now time.Time) {
	if ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pos.Remove(ip)
	c.neg.Add(ip, now.Add(ttl))
}

// Delete removes ip from both positive and negative caches.
func (c *ReaderCache) Delete(ip string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pos.Remove(ip)
	c.neg.Remove(ip)
}
