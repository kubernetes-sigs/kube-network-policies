package networkpolicy

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"syscall"

	v1 "k8s.io/api/core/v1"
)

type packet struct {
	id      uint32
	family  v1.IPFamily
	srcIP   net.IP
	dstIP   net.IP
	proto   v1.Protocol // Set only for TCP, UDP and SCTP
	ipproto int
	srcPort int
	dstPort int
	payload []byte
}

var ErrorTooShort = fmt.Errorf("packet too short")
var ErrorCorrupted = fmt.Errorf("packet corrupted")
var ErrorExtensionHeader = fmt.Errorf("unsupported extension header")

func (p packet) String() string {
	return fmt.Sprintf("[%d] %s:%d %s:%d %s\n%s", p.id, p.srcIP.String(), p.srcPort, p.dstIP.String(), p.dstPort, p.proto, hex.Dump(p.payload))
}

// https://en.wikipedia.org/wiki/Internet_Protocol_version_4#Packet_structure
// https://en.wikipedia.org/wiki/IPv6_packet
// https://github.com/golang/net/blob/master/ipv4/header.go
func parsePacket(b []byte) (packet, error) {
	t := packet{}
	if len(b) < 20 {
		// 20 is the minimum length of an IPv4 header (IPv6 is 40)
		return t, ErrorTooShort
	}
	version := int(b[0] >> 4)
	// initialize variables
	var l4offset, nxtHeader int
	switch version {
	case 4:
		t.family = v1.IPv4Protocol
		hdrlen := int(b[0]&0x0f) * 4 // (header length in 32-bit words)
		if hdrlen < 20 {
			return t, ErrorCorrupted
		}
		l4offset = hdrlen
		if l4offset >= len(b) {
			return t, ErrorTooShort
		}
		t.srcIP = net.IPv4(b[12], b[13], b[14], b[15])
		t.dstIP = net.IPv4(b[16], b[17], b[18], b[19])
		t.ipproto = int(b[9])
		// IPv4 fragments:
		// Since the conntracker is always used in K8s, IPv4 fragments
		// will never be passed via the nfqueue. Packets are
		// re-assembled by the kernel. Please see:
		// https://unix.stackexchange.com/questions/650790/unwanted-defragmentation-of-forwarded-ipv4-packets
	case 6:
		t.family = v1.IPv6Protocol
		if len(b) < 48 {
			// 40 is the length of an IPv6 header, and 8 is the
			// minimum lenght of an extension or L4 header
			return t, ErrorTooShort
		}
		t.srcIP = make(net.IP, net.IPv6len)
		copy(t.srcIP, b[8:24])
		t.dstIP = make(net.IP, net.IPv6len)
		copy(t.dstIP, b[24:40])
		// Handle extension headers.
		nxtHeader = int(b[6])
		l4offset = 40
		for nxtHeader == syscall.IPPROTO_DSTOPTS || nxtHeader == syscall.IPPROTO_HOPOPTS || nxtHeader == syscall.IPPROTO_ROUTING {
			if nxtHeader == syscall.IPPROTO_ROUTING {
				// IPv6 routing headers are too complex to process (e.g. SRv6),
				// and they should not be seen inside the cluster
				return t, ErrorExtensionHeader
			}
			// These headers have a lenght in 8-octet units, not
			// including the first 8 octets
			nxtHeader = int(b[l4offset])
			l4offset += (8 + int(b[l4offset+1])*8)
			// Now l4offset points to either another extension header,
			// or an L4 header. So we must have at least 8 byte data
			// after this (minimum extension header size)
			if (l4offset + 8) >= len(b) {
				return t, ErrorTooShort
			}
		}
		if nxtHeader == syscall.IPPROTO_FRAGMENT {
			// Only the first fragment has the L4 header
			fragOffset := int(binary.BigEndian.Uint16(b[l4offset+2 : l4offset+4]))
			if fragOffset&0xfff8 == 0 {
				nxtHeader = int(b[l4offset])
				l4offset += 8
				// We only handle extension headers in the recommended
				// order. After a fragment header, only
				// IPPROTO_DSTOPTS extension headers are accepted
				for nxtHeader == syscall.IPPROTO_DSTOPTS {
					nxtHeader = int(b[l4offset])
					l4offset += (8 + int(b[l4offset+1])*8)
					if (l4offset + 8) >= len(b) {
						return t, ErrorTooShort
					}
				}
				if nxtHeader == syscall.IPPROTO_HOPOPTS || nxtHeader == syscall.IPPROTO_ROUTING || nxtHeader == syscall.IPPROTO_FRAGMENT {
					// Extension headers out-of-order
					return t, ErrorExtensionHeader
				}
			} else {
				// Not first fragment, we have no L4 header and the
				// payload begins after this header (don't care about
				// extra extension headers) Return a packet with t.proto unset
				t.ipproto = syscall.IPPROTO_FRAGMENT
				return t, nil
			}
		}
		t.ipproto = nxtHeader
	default:
		return t, fmt.Errorf("unknown version %d", version)
	}

	// The payload follows immediately after the L4 header, pointed
	// out by 'l4offset'. So payloadOffset will be (l4offset + the
	// L4header len) The L4header len is 8 byte for udp and sctp, but
	// may vary for tcp (the dataOffset)
	var payloadOffset int
	switch t.ipproto {
	case syscall.IPPROTO_TCP:
		t.proto = v1.ProtocolTCP
		dataOffset := int(b[l4offset+12]>>4) * 4
		if dataOffset < 20 {
			return t, ErrorCorrupted
		}
		payloadOffset = l4offset + dataOffset
	case syscall.IPPROTO_UDP:
		t.proto = v1.ProtocolUDP
		payloadOffset = l4offset + 8
	case syscall.IPPROTO_SCTP:
		t.proto = v1.ProtocolSCTP
		payloadOffset = l4offset + 8
	default:
		// Return a packet with t.proto unset, and ports 0
		return t, nil
	}
	if payloadOffset > len(b) {
		// If the payloadOffset is beyond the packet size, we have an
		// incomplete L4 header
		return t, ErrorTooShort
	}

	t.srcPort = int(binary.BigEndian.Uint16(b[l4offset : l4offset+2]))
	t.dstPort = int(binary.BigEndian.Uint16(b[l4offset+2 : l4offset+4]))

	// TODO allow to filter by the payload
	t.payload = b[payloadOffset:]
	return t, nil
}
