// SPDX-License-Identifier: APACHE-2.0

package networkpolicy

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/armon/go-radix"
	"github.com/google/go-cmp/cmp"
	"github.com/vishvananda/netns"
	"golang.org/x/net/dns/dnsmessage"
	v1 "k8s.io/api/core/v1"
	testingclock "k8s.io/utils/clock/testing"
)

func TestDomainCache_syncRules(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges.")
	}

	expectedNftables := `
table inet kube-network-policies-dnscache {
        chain postrouting {
                type filter hook postrouting priority 2147483647; policy accept;
                udp sport 53 counter packets 0 bytes 0 queue flags bypass to 121
        }
}
`
	n := NewDomainCache(121)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Save the current network namespace
	origns, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer origns.Close()

	// Create a new network namespace
	newns, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	defer newns.Close()

	if err := n.syncRules(); err != nil {
		t.Fatalf("NewDomainCache.syncRules() error = %v", err)
	}

	cmd := exec.Command("nft", "list", "table", "inet", tableName)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("nft list table error = %v", err)
	}
	got := string(out)
	if !compareMultilineStringsIgnoreIndentation(got, expectedNftables) {
		t.Errorf("Got:\n%s\nExpected:\n%s\nDiff:\n%s", got, expectedNftables, cmp.Diff(got, expectedNftables))
	}
	n.cleanRules()
	cmd = exec.Command("nft", "list", "table", "inet", tableName)
	out, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("nft list ruleset unexpected success")
	}
	if !strings.Contains(string(out), "No such file or directory") {
		t.Errorf("unexpected error %v %s", err, string(out))
	}
	// Switch back to the original namespace
	netns.Set(origns)
}

// buildIPv4Header creates a minimal IPv4 header.
func buildIPv4Header(srcIP, dstIP net.IP, payloadLen int) []byte {
	hdr := make([]byte, 20)
	hdr[0] = (4 << 4) | (20 / 4) // Version 4, Header Length 20 bytes
	// hdr[1] = 0 // DSCP, ECN
	totalLen := 20 + 8 + payloadLen // IP Hdr + UDP Hdr + DNS Payload
	binary.BigEndian.PutUint16(hdr[2:4], uint16(totalLen))
	// hdr[4:6] // Identification
	// hdr[6:8] // Flags, Fragment Offset
	hdr[8] = 64 // TTL
	hdr[9] = syscall.IPPROTO_UDP
	// hdr[10:12] // Header Checksum (set to 0 for simplicity in tests)
	copy(hdr[12:16], srcIP.To4())
	copy(hdr[16:20], dstIP.To4())
	// TODO: Calculate checksum if needed, but often ignored by stack/nflog
	return hdr
}

// buildUDPHeader creates a minimal UDP header.
func buildUDPHeader(srcPort, dstPort uint16, payloadLen int) []byte {
	hdr := make([]byte, 8)
	udpLen := 8 + payloadLen
	binary.BigEndian.PutUint16(hdr[0:2], srcPort)
	binary.BigEndian.PutUint16(hdr[2:4], dstPort)
	binary.BigEndian.PutUint16(hdr[4:6], uint16(udpLen))
	// hdr[6:8] // Checksum (set to 0 for simplicity in tests)
	// TODO: Calculate checksum if needed
	return hdr
}

func TestDomainCache_HandleDNSPacket(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name       string
		queryName  string
		queryType  dnsmessage.Type
		answerIPs  []net.IP
		srcIPStr   string
		dstIPStr   string
		dstPort    uint16
		expectIPv4 bool // True if we expect IPv4 in cache, false for IPv6
	}{
		{
			name:       "A Record",
			queryName:  "www.example.com.",
			queryType:  dnsmessage.TypeA,
			answerIPs:  []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2")},
			srcIPStr:   "10.0.0.53", // Simulating DNS server IP
			dstIPStr:   "10.1.1.10", // Simulating client Pod IP
			dstPort:    54321,       // Client ephemeral port
			expectIPv4: true,
		},
		{
			name:       "AAAA Record",
			queryName:  "ipv6.example.org.",
			queryType:  dnsmessage.TypeAAAA,
			answerIPs:  []net.IP{net.ParseIP("2001:db8::1")},
			srcIPStr:   "10.0.0.53",
			dstIPStr:   "10.1.1.11",
			dstPort:    54322,
			expectIPv4: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Now()
			fakeClock := testingclock.NewFakeClock(now)
			n := &DomainCache{
				cache: &domainMap{
					clock: fakeClock,
					tree:  radix.New(),
				},
			}
			// 1. Forge DNS Response Payload
			q := dnsmessage.Question{
				Name:  mustNewName(tt.queryName),
				Type:  tt.queryType,
				Class: dnsmessage.ClassINET,
			}
			hdr := dnsmessage.Header{
				ID:            1234, // Arbitrary ID
				Response:      true,
				Authoritative: true,
			}
			builder := dnsmessage.NewBuilder(nil, hdr)
			builder.EnableCompression()
			err := builder.StartQuestions()
			if err != nil {
				t.Fatalf("builder.StartQuestions() failed: %v", err)
			}
			err = builder.Question(q)
			if err != nil {
				t.Fatalf("builder.Question() failed: %v", err)
			}
			err = builder.StartAnswers()
			if err != nil {
				t.Fatalf("builder.StartAnswers() failed: %v", err)
			}

			rscHdr := dnsmessage.ResourceHeader{
				Name:  q.Name,
				Type:  q.Type,
				Class: q.Class,
				TTL:   uint32(expireTimeout.Seconds()), // Use expireTimeout for TTL
			}

			for _, ip := range tt.answerIPs {
				if tt.expectIPv4 && ip.To4() != nil {
					err = builder.AResource(rscHdr, dnsmessage.AResource{A: [4]byte(ip.To4())})
					if err != nil {
						t.Fatalf("builder.AResource() failed: %v", err)
					}
				} else if !tt.expectIPv4 && ip.To16() != nil && ip.To4() == nil {
					err = builder.AAAAResource(rscHdr, dnsmessage.AAAAResource{AAAA: [16]byte(ip.To16())})
					if err != nil {
						t.Fatalf("builder.AAAAResource() failed: %v", err)
					}
				}
			}

			dnsPayload, err := builder.Finish()
			if err != nil {
				t.Fatalf("builder.Finish() failed: %v", err)
			}

			// 2. Forge IP/UDP Packet
			srcIP := net.ParseIP(tt.srcIPStr)
			dstIP := net.ParseIP(tt.dstIPStr)
			udpHeader := buildUDPHeader(53, tt.dstPort, len(dnsPayload)) // Source port is 53 for DNS response
			ipHeader := buildIPv4Header(srcIP, dstIP, len(dnsPayload))   // Assuming IPv4 for simplicity
			rawPacketBytes := append(ipHeader, append(udpHeader, dnsPayload...)...)

			// 3. Parse the Raw Packet
			parsedPacket, err := parsePacket(rawPacketBytes)
			if err != nil {
				t.Fatalf("parsePacket() failed: %v", err)
			}
			if parsedPacket.proto != v1.ProtocolUDP {
				t.Errorf("Parsed protocol mismatch: got %v, want %v", parsedPacket.proto, v1.ProtocolUDP)
			}
			if parsedPacket.srcPort != 53 {
				t.Errorf("Parsed source port mismatch: got %d, want %d", parsedPacket.srcPort, 53)
			}
			if parsedPacket.dstPort != int(tt.dstPort) {
				t.Errorf("Parsed destination port mismatch: got %d, want %d", parsedPacket.dstPort, tt.dstPort)
			}
			if !srcIP.Equal(parsedPacket.srcIP) {
				t.Errorf("Parsed source IP mismatch: got %v, want %v", parsedPacket.srcIP, srcIP)
			}
			if !dstIP.Equal(parsedPacket.dstIP) {
				t.Errorf("Parsed destination IP mismatch: got %v, want %v", parsedPacket.dstIP, dstIP)
			}
			if !bytes.Equal(dnsPayload, parsedPacket.payload) {
				t.Errorf("Parsed payload mismatch: got %x, want %x", parsedPacket.payload, dnsPayload)
			}

			// 4. Process with handleDNSPacket
			n.handleDNSPacket(ctx, parsedPacket)

			// 5. Verify Cache
			// Check if *each* expected IP is associated with the domain
			foundCount := 0
			for _, expectedIP := range tt.answerIPs {
				// Need to check the correct domain name (without trailing dot for storage)
				if ok := n.cache.containsIP(strings.TrimSuffix(tt.queryName, "."), expectedIP); ok {
					t.Logf("Successfully found %s -> %s in cache", tt.queryName, expectedIP)
					foundCount++
				} else {
					t.Errorf("Expected to find %s -> %s in cache, but it was missing", tt.queryName, expectedIP)
				}
			}
			if foundCount != len(tt.answerIPs) {
				t.Errorf("Expected %d IPs in cache for %s, but found %d", len(tt.answerIPs), tt.queryName, foundCount)
			}

			fakeClock.Step(expireTimeout + time.Second)
			n.cache.gc() // Explicitly call GC for testing
			for _, expectedIP := range tt.answerIPs {
				storedDomain := strings.TrimSuffix(tt.queryName, ".")
				if ok := n.cache.containsIP(storedDomain, expectedIP); ok {
					t.Errorf("Expected %s -> %s to be expired and removed from cache, but it was still present", storedDomain, expectedIP)
				}
			}

		})
	}
}

func mustNewName(name string) dnsmessage.Name {
	nn, err := dnsmessage.NewName(name)
	if err != nil {
		panic(fmt.Sprint("creating name: ", err))
	}
	return nn
}
