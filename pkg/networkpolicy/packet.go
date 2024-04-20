package networkpolicy

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"

	v1 "k8s.io/api/core/v1"
)

type packet struct {
	family  v1.IPFamily
	srcIP   net.IP
	dstIP   net.IP
	proto   v1.Protocol
	srcPort int
	dstPort int
	payload []byte
}

func (p packet) String() string {
	return fmt.Sprintf("%s:%d %s:%d %s :: %s", p.srcIP.String(), p.srcPort, p.dstIP.String(), p.dstPort, p.proto, hex.Dump(p.payload))
}

// https://en.wikipedia.org/wiki/Internet_Protocol_version_4#Packet_structure
// https://en.wikipedia.org/wiki/IPv6_packet
// https://github.com/golang/net/blob/master/ipv4/header.go
func parsePacket(b []byte) (packet, error) {
	t := packet{}
	if b == nil {
		return t, fmt.Errorf("empty payload")
	}
	version := int(b[0] >> 4)
	// initialize variables
	var hdrlen, protocol int
	switch version {
	case 4:
		t.family = v1.IPv4Protocol
		hdrlen = int(b[0]&0x0f) << 2
		if len(b) < hdrlen+4 {
			return t, fmt.Errorf("payload to short, received %d expected at least %d", len(b), hdrlen+4)
		}
		t.srcIP = net.IPv4(b[12], b[13], b[14], b[15])
		t.dstIP = net.IPv4(b[16], b[17], b[18], b[19])
		protocol = int(b[9])
	case 6:
		t.family = v1.IPv6Protocol
		hdrlen = 40
		if len(b) < hdrlen+4 {
			return t, fmt.Errorf("payload to short, received %d expected at least %d", len(b), hdrlen+4)
		}
		t.srcIP = make(net.IP, net.IPv6len)
		copy(t.srcIP, b[8:24])
		t.dstIP = make(net.IP, net.IPv6len)
		copy(t.dstIP, b[24:40])
		// NextHeader (not extension headers supported)
		protocol = int(b[6])
	default:
		return t, fmt.Errorf("unknown versions %d", version)
	}

	var dataOffset int
	switch protocol {
	case 6:
		t.proto = v1.ProtocolTCP
		dataOffset = int(b[hdrlen+12] >> 4) // data offset
	case 17:
		t.proto = v1.ProtocolUDP
		dataOffset = hdrlen + 8 // data starts after
	case 132:
		t.proto = v1.ProtocolSCTP
		dataOffset = hdrlen + 8
	default:
		return t, fmt.Errorf("unknown protocol %d", protocol)
	}
	// TCP, UDP and SCTP srcPort and dstPort are the first 4 bytes after the IP header
	t.srcPort = int(binary.BigEndian.Uint16(b[hdrlen : hdrlen+2]))
	t.dstPort = int(binary.BigEndian.Uint16(b[hdrlen+2 : hdrlen+4]))
	// Obtain the offset of the payload
	// TODO allow to filter by the payload
	if len(b) >= hdrlen+dataOffset {
		t.payload = b[hdrlen+dataOffset:]
	}
	return t, nil
}
