// SPDX-License-Identifier: APACHE-2.0

package networkpolicy

import (
	"net"
	"strings"
	"sync"
	"time"

	"github.com/armon/go-radix"
	"k8s.io/utils/clock"
	utilsnet "k8s.io/utils/net"
)

type ipEntry struct {
	expireTime time.Time
	ips        utilsnet.IPSet
}

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

	now := i.clock.Now()

	ipset := make(utilsnet.IPSet)
	ipset.Insert(ips...)

	i.tree.Insert(domain, ipEntry{
		expireTime: now.Add(finalTTL),
		ips:        ipset,
	})
}

// contains returns true if the given domain contains the specified IP
func (i *domainMap) containsIP(domain string, ip net.IP) bool {
	i.mu.RLock()
	defer i.mu.RUnlock()
	var entry ipEntry
	var ok bool
	// reverse the domain since the radix tree match on prefixes
	domain = reverseDomain(domain)
	// wildcard
	var foundInWildcard bool
	if strings.HasSuffix(domain, "*") {
		i.tree.WalkPrefix(strings.TrimSuffix(domain, "*"), func(d string, v interface{}) bool {
			entry, ok = v.(ipEntry)
			if !ok {
				return false
			}
			// check if the entry is still valid
			if entry.expireTime.Before(i.clock.Now()) {
				return false
			}
			if entry.ips.Has(ip) {
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

		entry, ok = v.(ipEntry)
		if !ok {
			return false
		}

		// check if the entry is still valid
		if entry.expireTime.Before(i.clock.Now()) {
			return false
		}
		return entry.ips.Has(ip)
	}
}

func (i *domainMap) gc() {
	i.mu.Lock()
	defer i.mu.Unlock()
	expiredDomains := []string{}
	i.tree.Walk(func(domain string, v interface{}) bool {
		if entry, ok := v.(ipEntry); ok && entry.expireTime.Before(i.clock.Now()) {
			expiredDomains = append(expiredDomains, domain)
		}
		return false
	})

	for _, domain := range expiredDomains {
		i.tree.Delete(domain)
	}
}
