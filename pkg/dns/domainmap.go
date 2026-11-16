// SPDX-License-Identifier: APACHE-2.0

package dns

import (
	"net"
	"strings"
	"sync"
	"time"

	"github.com/armon/go-radix"
	"k8s.io/utils/clock"
)

// ipEntry is what the cache knows about one IP address a domain resolved to.
type ipEntry struct {
	// expires is the end of the TTL of the DNS answer. New connections match
	// the entry until then.
	expires time.Time
	// retainUntil is staleRetention after the last time a connection matched
	// the entry. Established connections keep matching the entry after it
	// expired and gc keeps it until then, so an entry stays as long as the
	// firewall enforcer finds connections that depend on it.
	retainUntil time.Time
}

type ipEntries map[string]*ipEntry // ip : entry

type domainMap struct {
	mu    sync.Mutex
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
		if e, ok := entries[ip.String()]; ok {
			// e.retainUntil remains unchanged
			e.expires = expireTime
			continue
		}
		entries[ip.String()] = &ipEntry{expires: expireTime}
	}
	i.tree.Insert(domain, entries)
}

// containsIP returns true if the given domain resolved to the specified IP.
// A new connection matches an entry within the TTL of its answer. An
// established connection also matches an expired entry, the expiry of a DNS
// record stops new connections to the IP and keeps the existing ones. A match
// refreshes the entry so gc keeps it while connections use it.
func (i *domainMap) containsIP(domain string, ip net.IP, established bool) bool {
	i.mu.Lock()
	defer i.mu.Unlock()

	now := i.clock.Now()
	key := ip.String()
	match := func(entries ipEntries) bool {
		e, ok := entries[key]
		if !ok {
			return false
		}
		if !established && !e.expires.After(now) {
			return false
		}
		e.retainUntil = now.Add(staleRetention)
		return true
	}

	// reverse the domain since the radix tree match on prefixes
	domain = reverseDomain(domain)
	// wildcard
	if strings.HasSuffix(domain, "*") {
		var foundInWildcard bool
		i.tree.WalkPrefix(strings.TrimSuffix(domain, "*"), func(d string, v interface{}) bool {
			entries, ok := v.(ipEntries)
			if !ok {
				return false
			}
			if match(entries) {
				foundInWildcard = true
				return true
			}
			return false
		})
		return foundInWildcard
	}
	// exact match
	v, ok := i.tree.Get(domain)
	if !ok {
		return false
	}
	entries, ok := v.(ipEntries)
	if !ok {
		return false
	}
	return match(entries)
}

// gc removes the entries that expired and that no connection matched for
// staleRetention.
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
		for ip, e := range entries {
			if e.expires.After(now) || e.retainUntil.After(now) {
				newEntries[ip] = e
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
