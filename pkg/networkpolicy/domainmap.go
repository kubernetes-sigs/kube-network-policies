// SPDX-License-Identifier: APACHE-2.0

package networkpolicy

import (
	"net"
	"strings"
	"sync"
	"time"

	"github.com/armon/go-radix"
	"k8s.io/utils/clock"
)

type ipEntries map[string]time.Time // ip : expire time

type domainMap struct {
	mu    sync.RWMutex
	clock clock.Clock
	tree  *radix.Tree
}

// reverseDomain reverses a domain name string.
func reverseDomain(domain string) string {
	parts := strings.Split(domain, ".")
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return strings.Join(parts, ".")
}

func (i *domainMap) add(domain string, ips []net.IP, ttl int) {
	i.mu.Lock()
	defer i.mu.Unlock()
	// reverse the domain since the radix tree match on prefixes
	domain = reverseDomain(domain)
	// default ttl
	var finalTTL time.Duration
	if ttl == 0 {
		finalTTL = expireTimeout
	} else {
		finalTTL = time.Duration(ttl) * time.Second
	}
	// cap max ttl
	if finalTTL > maxTTL {
		finalTTL = maxTTL
	}
	expireTime := i.clock.Now().Add(finalTTL)
	var entries ipEntries
	v, ok := i.tree.Get(domain)
	if !ok {
		entries = make(ipEntries)
	} else {
		entries = v.(ipEntries)
	}
	for _, ip := range ips {
		entries[ip.String()] = expireTime
	}
	i.tree.Insert(domain, entries)
}

// contains returns true if the given domain contains the specified IP
func (i *domainMap) containsIP(domain string, ip net.IP) bool {
	i.mu.RLock()
	defer i.mu.RUnlock()

	// reverse the domain since the radix tree match on prefixes
	domain = reverseDomain(domain)
	// wildcard
	var foundInWildcard bool
	if strings.HasSuffix(domain, "*") {
		i.tree.WalkPrefix(strings.TrimSuffix(domain, "*"), func(d string, v interface{}) bool {
			entries, ok := v.(ipEntries)
			if !ok {
				return false
			}
			if v, ok := entries[ip.String()]; ok && v.After(i.clock.Now()) {
				foundInWildcard = true
				return true
			}
			return false
		})
		return foundInWildcard
	} else {
		// exact match
		v, ok := i.tree.Get(domain)
		if !ok {
			return false
		}

		entries, ok := v.(ipEntries)
		if !ok {
			return false
		}

		// check if the entry is still valid
		if v, ok := entries[ip.String()]; ok && v.After(i.clock.Now()) {
			return true
		}
		return false
	}
}

func (i *domainMap) gc() {
	i.mu.Lock()
	defer i.mu.Unlock()
	now := i.clock.Now()
	newTree := radix.New()
	i.tree.Walk(func(domain string, v interface{}) bool {
		entries, ok := v.(ipEntries)
		if !ok {
			return false
		}
		newEntries := make(ipEntries)
		for ip, expiredTime := range entries {
			if expiredTime.After(now) {
				newEntries[ip] = expiredTime
			}
		}
		if len(newEntries) > 0 {
			newTree.Insert(domain, newEntries)
		}
		return false
	})

	i.tree = nil
	i.tree = newTree
}
