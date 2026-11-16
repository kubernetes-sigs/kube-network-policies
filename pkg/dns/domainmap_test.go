// SPDX-License-Identifier: APACHE-2.0

package dns

import (
	"net"
	"testing"
	"time"

	"github.com/armon/go-radix"
	testingclock "k8s.io/utils/clock/testing"

	"sigs.k8s.io/kube-network-policies/pkg/dataplane"
)

func TestReverseDomain(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", ""},
		{"com", "com"},
		{"example.com", "com.example"},
		{"www.example.com", "com.example.www"},
		{"a.b.c.d", "d.c.b.a"},
		{"*.b.c.d", "d.c.b.*"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := reverseDomain(tt.input); got != tt.want {
				t.Errorf("reverseDomain(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestIPCache(t *testing.T) {
	clock := testingclock.NewFakeClock(time.Now())
	c := &domainMap{
		clock: clock,
		tree:  radix.New(),
	}

	hostv4 := "host.com"
	hostv6 := "hostv6.com"
	ip4 := net.ParseIP("1.2.3.4")
	ip4_2 := net.ParseIP("5.6.7.8")
	ip6 := net.ParseIP("2001:db8::1")

	// Test adding and retrieving IPv4 and IPv6 entries
	c.add(hostv4, []net.IP{ip4, ip4_2}, int(maxTTL.Seconds()))
	c.add(hostv6, []net.IP{ip6}, int(maxTTL.Seconds()))

	if ok := c.containsIP(hostv4, ip4, false); !ok {
		t.Errorf("Failed to retrieve IPv4 entry")
	}
	if ok := c.containsIP(hostv4, ip4_2, false); !ok {
		t.Errorf("Failed to retrieve IPv4 entry")
	}
	if ok := c.containsIP(hostv6, ip6, false); !ok {
		t.Errorf("Failed to retrieve IPv6 entry")
	}

	// Test retrieving non-existent entry
	if ok := c.containsIP("nonexistent.com", ip4, false); ok {
		t.Errorf("Retrieved non-existent entry")
	}

	// Test expire entries
	clock.SetTime(clock.Now().Add(time.Hour))

	if ok := c.containsIP(hostv4, ip4, false); ok {
		t.Errorf("Unexpected entry")
	}
	if ok := c.containsIP(hostv6, ip6, false); ok {
		t.Errorf("Unexpected entry")
	}

}

func TestIPCacheGC(t *testing.T) {
	clock := testingclock.NewFakeClock(time.Now())
	c := &domainMap{
		clock: clock,
		tree:  radix.New(),
	}

	hostv4 := "host.com"
	hostv6 := "hostv6.com"
	ip4 := net.ParseIP("1.2.3.4")
	ip6 := net.ParseIP("2001:db8::1")

	// Test adding and retrieving IPv4 and IPv6 entries
	c.add(hostv4, []net.IP{ip4}, int(expireTimeout.Seconds()))
	c.add(hostv6, []net.IP{ip6}, int(maxTTL.Seconds()))

	if ok := c.containsIP(hostv4, ip4, false); !ok {
		t.Errorf("Failed to retrieve IPv4 entry")
	}
	if ok := c.containsIP(hostv6, ip6, false); !ok {
		t.Errorf("Failed to retrieve IPv6 entry")
	}
	// Test expire entries
	clock.SetTime(clock.Now().Add(maxTTL - 1*time.Second))
	c.gc()

	if ok := c.containsIP(hostv4, ip4, false); ok {
		t.Errorf("Unexpected entry")
	}
	if ok := c.containsIP(hostv6, ip6, false); !ok {
		t.Errorf("expected entry")
	}
}

func TestDomainMap_Wildcard(t *testing.T) {
	now := time.Now()
	clock := testingclock.NewFakeClock(now)
	c := &domainMap{
		clock: clock,
		tree:  radix.New(),
	}

	wildcardHost := "*.example.com"
	specificHost := "www.example.com"
	otherHost := "test.org"
	ipExample := net.ParseIP("5.6.7.8")
	ipOther := net.ParseIP("4.3.2.1")

	c.add(specificHost, []net.IP{ipExample}, int(expireTimeout.Seconds()))
	c.add(otherHost, []net.IP{ipOther}, int(expireTimeout.Seconds()))

	t.Run("Wildcard match", func(t *testing.T) {
		if ok := c.containsIP(wildcardHost, ipExample, false); !ok {
			t.Errorf("containsIP(%q, %q) with wildcard = false, want true", wildcardHost, ipExample)
		}
	})

	t.Run("Wildcard no match IP", func(t *testing.T) {
		if ok := c.containsIP(wildcardHost, ipOther, false); ok {
			t.Errorf("containsIP(%q, %q) with wildcard = true, want false", wildcardHost, ipOther)
		}
	})

	t.Run("Wildcard no match domain", func(t *testing.T) {
		if ok := c.containsIP("another.domain.org", ipExample, false); ok {
			t.Errorf("containsIP(%q, %q) with wildcard = true, want false", "another.domain.org", ipExample)
		}
	})

	t.Run("Wildcard expiration", func(t *testing.T) {
		clock.SetTime(now.Add(expireTimeout).Add(time.Second))
		if ok := c.containsIP(wildcardHost, ipExample, false); ok {
			t.Errorf("containsIP(%q, %q) after wildcard expiration = true, want false", specificHost, ipExample)
		}
	})
}

// An expired answer stops new connections and keeps the established ones,
// that keep matching while they use the entry.
// https://github.com/kubernetes-sigs/kube-network-policies/issues/439
func TestDomainMap_EstablishedConnections(t *testing.T) {
	now := time.Now()
	clock := testingclock.NewFakeClock(now)
	c := &domainMap{
		clock: clock,
		tree:  radix.New(),
	}

	host := "echo.repro.test"
	wildcard := "*.repro.test"
	ip := net.ParseIP("172.18.0.3")
	ttl := 5

	c.add(host, []net.IP{ip}, ttl)
	// the connection opens while the answer is valid
	if !c.containsIP(host, ip, false) {
		t.Fatalf("containsIP(%q, %q, new) within the TTL = false, want true", host, ip)
	}

	clock.SetTime(now.Add(time.Duration(ttl) * time.Second).Add(time.Second))
	if c.containsIP(host, ip, false) {
		t.Errorf("containsIP(%q, %q, new) after the TTL = true, want false", host, ip)
	}
	if !c.containsIP(host, ip, true) {
		t.Errorf("containsIP(%q, %q, established) after the TTL = false, want true", host, ip)
	}
	if c.containsIP(wildcard, ip, false) {
		t.Errorf("containsIP(%q, %q, new) after the TTL = true, want false", wildcard, ip)
	}
	if !c.containsIP(wildcard, ip, true) {
		t.Errorf("containsIP(%q, %q, established) after the TTL = false, want true", wildcard, ip)
	}

	// gc keeps the expired entry while connections use it, each run of the
	// firewall enforcer evaluates them.
	for i := 0; i < 3; i++ {
		clock.SetTime(clock.Now().Add(dataplane.FirewallEnforcerMaxInterval))
		c.gc()
		if !c.containsIP(host, ip, true) {
			t.Fatalf("containsIP(%q, %q, established) after %d runs of the firewall enforcer = false, want true", host, ip, i+1)
		}
	}

	// once the connections are gone the entry is not refreshed and goes away
	clock.SetTime(clock.Now().Add(staleRetention).Add(time.Second))
	c.gc()
	if c.containsIP(host, ip, true) {
		t.Errorf("containsIP(%q, %q, established) %s after the last use = true, want false", host, ip, staleRetention)
	}

	// an expired entry that no connection used goes away when it expires
	unused := "unused.repro.test"
	c.add(unused, []net.IP{ip}, ttl)
	clock.SetTime(clock.Now().Add(time.Duration(ttl) * time.Second).Add(time.Second))
	c.gc()
	if c.containsIP(unused, ip, true) {
		t.Errorf("containsIP(%q, %q, established) after the TTL with no previous use = true, want false", unused, ip)
	}

	// an answer that did not resolve to the IP never matches
	other := net.ParseIP("172.18.0.4")
	if c.containsIP(host, other, true) {
		t.Errorf("containsIP(%q, %q, established) = true, want false", host, other)
	}
}

// A refreshed answer does not change until when the entry is retained, so gc
// keeps it for the connections that depend on it.
func TestDomainMap_RefreshKeepsRetention(t *testing.T) {
	now := time.Now()
	clock := testingclock.NewFakeClock(now)
	c := &domainMap{
		clock: clock,
		tree:  radix.New(),
	}

	host := "echo.repro.test"
	ip := net.ParseIP("172.18.0.3")
	ttl := 5

	c.add(host, []net.IP{ip}, ttl)
	if !c.containsIP(host, ip, false) {
		t.Fatalf("containsIP(%q, %q, new) within the TTL = false, want true", host, ip)
	}
	// a lookup refreshes the answer, nothing connects after it
	clock.SetTime(now.Add(2 * time.Second))
	c.add(host, []net.IP{ip}, ttl)

	clock.SetTime(now.Add(dataplane.FirewallEnforcerMaxInterval))
	c.gc()
	if !c.containsIP(host, ip, true) {
		t.Errorf("containsIP(%q, %q, established) at the next run of the firewall enforcer after the refresh = false, want true", host, ip)
	}
}
