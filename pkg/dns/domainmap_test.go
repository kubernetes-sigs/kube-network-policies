// SPDX-License-Identifier: APACHE-2.0

package dns

import (
	"net"
	"testing"
	"time"

	"github.com/armon/go-radix"
	testingclock "k8s.io/utils/clock/testing"
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

	if ok := c.containsIP(hostv4, ip4); !ok {
		t.Errorf("Failed to retrieve IPv4 entry")
	}
	if ok := c.containsIP(hostv4, ip4_2); !ok {
		t.Errorf("Failed to retrieve IPv4 entry")
	}
	if ok := c.containsIP(hostv6, ip6); !ok {
		t.Errorf("Failed to retrieve IPv6 entry")
	}

	// Test retrieving non-existent entry
	if ok := c.containsIP("nonexistent.com", ip4); ok {
		t.Errorf("Retrieved non-existent entry")
	}

	// Test expire entries
	clock.SetTime(clock.Now().Add(time.Hour))

	if ok := c.containsIP(hostv4, ip4); ok {
		t.Errorf("Unexpected entry")
	}
	if ok := c.containsIP(hostv6, ip6); ok {
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

	if ok := c.containsIP(hostv4, ip4); !ok {
		t.Errorf("Failed to retrieve IPv4 entry")
	}
	if ok := c.containsIP(hostv6, ip6); !ok {
		t.Errorf("Failed to retrieve IPv6 entry")
	}
	// Test expire entries
	clock.SetTime(clock.Now().Add(maxTTL - 1*time.Second))
	c.gc()

	if ok := c.containsIP(hostv4, ip4); ok {
		t.Errorf("Unexpected entry")
	}
	if ok := c.containsIP(hostv6, ip6); !ok {
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
		if ok := c.containsIP(wildcardHost, ipExample); !ok {
			t.Errorf("containsIP(%q, %q) with wildcard = false, want true", wildcardHost, ipExample)
		}
	})

	t.Run("Wildcard no match IP", func(t *testing.T) {
		if ok := c.containsIP(wildcardHost, ipOther); ok {
			t.Errorf("containsIP(%q, %q) with wildcard = true, want false", wildcardHost, ipOther)
		}
	})

	t.Run("Wildcard no match domain", func(t *testing.T) {
		if ok := c.containsIP("another.domain.org", ipExample); ok {
			t.Errorf("containsIP(%q, %q) with wildcard = true, want false", "another.domain.org", ipExample)
		}
	})

	t.Run("Wildcard expiration", func(t *testing.T) {
		clock.SetTime(now.Add(expireTimeout).Add(time.Second))
		if ok := c.containsIP(wildcardHost, ipExample); ok {
			t.Errorf("containsIP(%q, %q) after wildcard expiration = true, want false", specificHost, ipExample)
		}
	})
}
