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
	"net/netip"
	"sync"

	"sigs.k8s.io/kube-network-policies/pkg/api"
)

// LocalIPCache is an in-memory implementation of the IPCache interface.
type LocalIPCache struct {
	mu   sync.RWMutex
	data map[netip.Addr]*api.PodInfo
}

var _ Store = &LocalIPCache{}
var _ api.PodInfoProvider = &LocalIPCache{}

// NewLocalIPCache creates a new in-memory IP cache.
func NewLocalIPCache() *LocalIPCache {
	return &LocalIPCache{
		data: make(map[netip.Addr]*api.PodInfo),
	}
}

func (c *LocalIPCache) GetPodInfoByIP(ip string) (*api.PodInfo, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	key, err := netip.ParseAddr(ip)
	if err != nil {
		return nil, false
	}
	info, found := c.data[key]
	return info, found
}

func (c *LocalIPCache) Upsert(ip string, info *api.PodInfo) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	key, err := netip.ParseAddr(ip)
	if err != nil {
		return err
	}
	c.data[key] = info
	return nil
}

func (c *LocalIPCache) Delete(ip string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	key, err := netip.ParseAddr(ip)
	if err != nil {
		return err
	}
	delete(c.data, key)
	return nil
}

func (c *LocalIPCache) List() ([]*api.PodInfo, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var list []*api.PodInfo
	for _, info := range c.data {
		list = append(list, info)
	}
	return list, nil
}

func (c *LocalIPCache) Clear() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data = make(map[netip.Addr]*api.PodInfo)
	return nil
}

func (c *LocalIPCache) Close() error {
	return nil
}
