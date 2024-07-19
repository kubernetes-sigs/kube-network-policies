package networkpolicy

// Test data is generated from captured pcap file using:
// https://github.com/uablrek/pcap2go
// The used pcap files are stored in test-data/ and packet variables
// are commented with the originating pcap file

import (
	"net"
	"testing"

	v1 "k8s.io/api/core/v1"
)

func TestUDPFragmentIPv6(t *testing.T) {
	// The test-data contains 3 packets:
	// 1. First fragment of an UDP packet
	// 2. Fragment containing the rest of the UDP packet
	// 3. An unfragmented reply UDP packet
	// We expect:
	// 1. Identified as an UDP packet
	// 2. Unknown protocol (44)
	// 3. Identified as an UDP packet
	tests := []struct {
		name     string
		input    []byte
		err      bool
		expected packet
	}{
		{
			name:  "UDP first fragment",
			input: packetsUDPFragIPv6[0],
			expected: packet{
				family:  v1.IPv6Protocol,
				proto:   v1.ProtocolUDP,
				dstIP:   net.ParseIP("fd00::c0a8:101"),
				dstPort: 5001,
			},
		},
		{
			name:  "UDP not-first fragment",
			input: packetsUDPFragIPv6[1],
			expected: packet{
				family: v1.IPv6Protocol,
				dstIP:  net.ParseIP("fd00::c0a8:101"),
			},
		},
		{
			name:  "UDP packet (un-fragmented)",
			input: packetsUDPFragIPv6[2],
			expected: packet{
				family:  v1.IPv6Protocol,
				proto:   v1.ProtocolUDP,
				srcIP:   net.ParseIP("fd00::c0a8:101"),
				srcPort: 5001,
			},
		},
	}
	for _, tc := range tests {
		packet, err := parsePacket(tc.input)
		if err != nil {
			if !tc.err {
				t.Fatalf("%s: unexpected error: %v", tc.name, err)
			}
			continue
		}
		comparePacket(t, tc.name, tc.expected, packet)
	}
}

func TestTCPIPv4(t *testing.T) {
	// A normal TCP session with IPv4
	tests := []struct {
		name     string
		input    []byte
		err      bool
		expected packet
	}{
		{
			name:  "SYN",
			input: packetsTCPIPv4[0],
			expected: packet{
				family:  v1.IPv4Protocol,
				proto:   v1.ProtocolTCP,
				dstIP:   net.ParseIP("192.168.1.1"),
				dstPort: 5001,
				srcIP:   net.ParseIP("192.168.1.201"),
			},
		},
		{
			name:  "SYN, ACK",
			input: packetsTCPIPv4[1],
			expected: packet{
				family:  v1.IPv4Protocol,
				proto:   v1.ProtocolTCP,
				dstIP:   net.ParseIP("192.168.1.201"),
				srcIP:   net.ParseIP("192.168.1.1"),
				srcPort: 5001,
			},
		},
		{
			name:  "ACK 1",
			input: packetsTCPIPv4[2],
			expected: packet{
				family:  v1.IPv4Protocol,
				proto:   v1.ProtocolTCP,
				dstIP:   net.ParseIP("192.168.1.1"),
				dstPort: 5001,
				srcIP:   net.ParseIP("192.168.1.2+1"),
			},
		},
		{
			name:  "PSH, ACK",
			input: packetsTCPIPv4[3],
			expected: packet{
				family:  v1.IPv4Protocol,
				proto:   v1.ProtocolTCP,
				dstIP:   net.ParseIP("192.168.1.201"),
				srcIP:   net.ParseIP("192.168.1.1"),
				srcPort: 5001,
			},
		},
		{
			name:  "ACK 7",
			input: packetsTCPIPv4[4],
			expected: packet{
				family:  v1.IPv4Protocol,
				proto:   v1.ProtocolTCP,
				dstIP:   net.ParseIP("192.168.1.1"),
				dstPort: 5001,
				srcIP:   net.ParseIP("192.168.1.2+1"),
			},
		},
		{
			name:  "FIN, ACK 7",
			input: packetsTCPIPv4[5],
			expected: packet{
				family:  v1.IPv4Protocol,
				proto:   v1.ProtocolTCP,
				dstIP:   net.ParseIP("192.168.1.1"),
				dstPort: 5001,
				srcIP:   net.ParseIP("192.168.1.201"),
			},
		},
		{
			name:  "FIN, ACK 2",
			input: packetsTCPIPv4[6],
			expected: packet{
				family:  v1.IPv4Protocol,
				proto:   v1.ProtocolTCP,
				dstIP:   net.ParseIP("192.168.1.201"),
				srcIP:   net.ParseIP("192.168.1.1"),
				srcPort: 5001,
			},
		},
		{
			name:  "ACK 8",
			input: packetsTCPIPv4[7],
			expected: packet{
				family:  v1.IPv4Protocol,
				proto:   v1.ProtocolTCP,
				dstIP:   net.ParseIP("192.168.1.1"),
				dstPort: 5001,
				srcIP:   net.ParseIP("192.168.1.201"),
			},
		},
	}
	for _, tc := range tests {
		packet, err := parsePacket(tc.input)
		if err != nil {
			if !tc.err {
				t.Fatalf("%s: unexpected error: %v", tc.name, err)
			}
			continue
		}
		comparePacket(t, tc.name, tc.expected, packet)
	}
}

func TestTooShortPackets(t *testing.T) {
	// Length of: IPv6Header+fragmentHeader+udpHeader = 40+8+8 = 56
	rawPacket := packetsUDPFragIPv6[0]
	var err error
	// Test a nil packet
	_, err = parsePacket(nil)
	if err == nil {
		t.Fatalf("No error when parsing a nil-packet")
	}
	for i := 0; i < 56; i++ {
		_, err = parsePacket(rawPacket[:i])
		if err == nil {
			t.Fatalf("No error when parsing a packet, length=%d", i)
		}
	}
	_, err = parsePacket(rawPacket[:56])
	if err != nil {
		t.Fatalf("Error when parsing a complete packet")
	}
}

func comparePacket(t *testing.T, tc string, expected, got packet) {
	if got.family != expected.family {
		t.Fatalf("%s: family: expected=%v, got=%v", tc, expected.family, got.family)
	}
	if got.proto != expected.proto {
		t.Fatalf("%s: proto: expected=%v, got=%v", tc, expected.proto, got.proto)
	}
	// Compare other fields only if expected (never compare id and payload)
	if expected.srcIP != nil {
		if !got.srcIP.Equal(expected.srcIP) {
			t.Fatalf("%s: srcIP: expected=%v, got=%v", tc, expected.srcIP, got.srcIP)
		}
	}
	if expected.srcPort > 0 {
		if got.srcPort != expected.srcPort {
			t.Fatalf("%s: srcPort: expected=%v, got=%v", tc, expected.srcPort, got.srcPort)
		}
	}
	if expected.dstIP != nil {
		if !got.dstIP.Equal(expected.dstIP) {
			t.Fatalf("%s: dstIP: expected=%v, got=%v", tc, expected.dstIP, got.dstIP)
		}
	}
	if expected.dstPort > 0 {
		if got.dstPort != expected.dstPort {
			t.Fatalf("%s: dstPort: expected=%v, got=%v", tc, expected.dstPort, got.dstPort)
		}
	}
}

// pcap2go -cap 128 -variable packetsUDPFragIPv6 test-data/udp.pcap
var packetsUDPFragIPv6 = [][]byte{
	{
		0x60, 0x03, 0x65, 0x59, 0x05, 0x50, 0x2c, 0x40, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0xc9, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01, 0x11, 0x00, 0x00, 0x01, 0x97, 0x8d, 0xe1, 0x69,
		0xdd, 0xae, 0x13, 0x89, 0x07, 0x11, 0x6c, 0xec, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
		0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34,
		0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
		0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32,
	},
	{
		0x60, 0x03, 0x65, 0x59, 0x01, 0xd1, 0x2c, 0x40, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0xc9, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01, 0x11, 0x00, 0x05, 0x48, 0x97, 0x8d, 0xe1, 0x69,
		0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
		0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32,
		0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
		0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34,
	},
	{
		0x60, 0x03, 0x53, 0x6d, 0x00, 0x0e, 0x11, 0x40, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0xc9, 0x13, 0x89, 0xdd, 0xae, 0x00, 0x0e, 0x7e, 0x3c,
		0x76, 0x6d, 0x2d, 0x30, 0x30, 0x31,
	},
}

// pcap2go -cap 128 -variable packetsTCPIPv4 test-data/tcp-ipv4.pcap
var packetsTCPIPv4 = [][]byte{
	{
		0x45, 0x00, 0x00, 0x3c, 0x83, 0x11, 0x40, 0x00, 0x40, 0x06, 0x33, 0x90, 0xc0, 0xa8, 0x01, 0xc9,
		0xc0, 0xa8, 0x01, 0x01, 0xb6, 0xe2, 0x13, 0x89, 0x7f, 0x41, 0x17, 0x6c, 0x00, 0x00, 0x00, 0x00,
		0xa0, 0x02, 0xfa, 0xf0, 0x84, 0x49, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a,
		0x12, 0x20, 0x68, 0xba, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x06,
	},
	{
		0x45, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0xb6, 0xa1, 0xc0, 0xa8, 0x01, 0x01,
		0xc0, 0xa8, 0x01, 0xc9, 0x13, 0x89, 0xb6, 0xe2, 0x5f, 0x14, 0x6e, 0xe6, 0x7f, 0x41, 0x17, 0x6d,
		0xa0, 0x12, 0xfe, 0x88, 0x84, 0x49, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a,
		0x66, 0xb2, 0x32, 0xe0, 0x12, 0x20, 0x68, 0xba, 0x01, 0x03, 0x03, 0x07,
	},
	{
		0x45, 0x00, 0x00, 0x34, 0x83, 0x12, 0x40, 0x00, 0x40, 0x06, 0x33, 0x97, 0xc0, 0xa8, 0x01, 0xc9,
		0xc0, 0xa8, 0x01, 0x01, 0xb6, 0xe2, 0x13, 0x89, 0x7f, 0x41, 0x17, 0x6d, 0x5f, 0x14, 0x6e, 0xe7,
		0x80, 0x10, 0x03, 0xec, 0x84, 0x41, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x12, 0x20, 0x68, 0xbb,
		0x66, 0xb2, 0x32, 0xe0,
	},
	{
		0x45, 0x00, 0x00, 0x3a, 0x17, 0xbf, 0x40, 0x00, 0x40, 0x06, 0x9e, 0xe4, 0xc0, 0xa8, 0x01, 0x01,
		0xc0, 0xa8, 0x01, 0xc9, 0x13, 0x89, 0xb6, 0xe2, 0x5f, 0x14, 0x6e, 0xe7, 0x7f, 0x41, 0x17, 0x6d,
		0x80, 0x18, 0x01, 0xfe, 0x84, 0x47, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x66, 0xb2, 0x32, 0xe1,
		0x12, 0x20, 0x68, 0xbb, 0x76, 0x6d, 0x2d, 0x30, 0x30, 0x31,
	},
	{
		0x45, 0x00, 0x00, 0x34, 0x83, 0x13, 0x40, 0x00, 0x40, 0x06, 0x33, 0x96, 0xc0, 0xa8, 0x01, 0xc9,
		0xc0, 0xa8, 0x01, 0x01, 0xb6, 0xe2, 0x13, 0x89, 0x7f, 0x41, 0x17, 0x6d, 0x5f, 0x14, 0x6e, 0xed,
		0x80, 0x10, 0x03, 0xec, 0x84, 0x41, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x12, 0x20, 0x68, 0xbc,
		0x66, 0xb2, 0x32, 0xe1,
	},
	{
		0x45, 0x00, 0x00, 0x34, 0x83, 0x14, 0x40, 0x00, 0x40, 0x06, 0x33, 0x95, 0xc0, 0xa8, 0x01, 0xc9,
		0xc0, 0xa8, 0x01, 0x01, 0xb6, 0xe2, 0x13, 0x89, 0x7f, 0x41, 0x17, 0x6d, 0x5f, 0x14, 0x6e, 0xed,
		0x80, 0x11, 0x03, 0xec, 0x84, 0x41, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x12, 0x20, 0x68, 0xbc,
		0x66, 0xb2, 0x32, 0xe1,
	},
	{
		0x45, 0x00, 0x00, 0x34, 0x17, 0xc0, 0x40, 0x00, 0x40, 0x06, 0x9e, 0xe9, 0xc0, 0xa8, 0x01, 0x01,
		0xc0, 0xa8, 0x01, 0xc9, 0x13, 0x89, 0xb6, 0xe2, 0x5f, 0x14, 0x6e, 0xed, 0x7f, 0x41, 0x17, 0x6e,
		0x80, 0x11, 0x01, 0xfe, 0x84, 0x41, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x66, 0xb2, 0x32, 0xe1,
		0x12, 0x20, 0x68, 0xbc,
	},
	{
		0x45, 0x00, 0x00, 0x34, 0x83, 0x15, 0x40, 0x00, 0x40, 0x06, 0x33, 0x94, 0xc0, 0xa8, 0x01, 0xc9,
		0xc0, 0xa8, 0x01, 0x01, 0xb6, 0xe2, 0x13, 0x89, 0x7f, 0x41, 0x17, 0x6e, 0x5f, 0x14, 0x6e, 0xee,
		0x80, 0x10, 0x03, 0xec, 0x84, 0x41, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x12, 0x20, 0x68, 0xbc,
		0x66, 0xb2, 0x32, 0xe1,
	},
}