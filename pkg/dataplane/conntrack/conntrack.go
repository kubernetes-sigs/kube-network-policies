package conntrack

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
	"sigs.k8s.io/kube-network-policies/pkg/network"
)

var (
	mapIPFamilyToString = map[uint8]v1.IPFamily{
		unix.AF_INET:  v1.IPv4Protocol,
		unix.AF_INET6: v1.IPv6Protocol,
	}
	mapProtocolToString = map[uint8]v1.Protocol{
		unix.IPPROTO_TCP:  v1.ProtocolTCP,
		unix.IPPROTO_UDP:  v1.ProtocolUDP,
		unix.IPPROTO_SCTP: v1.ProtocolSCTP,
	}
)

func PacketFromFlow(flow *netlink.ConntrackFlow) *network.Packet {
	if flow == nil {
		return nil
	}
	packet := network.Packet{
		SrcIP:   flow.Forward.SrcIP,
		DstIP:   flow.Reverse.SrcIP,
		SrcPort: int(flow.Forward.SrcPort),
		DstPort: int(flow.Reverse.SrcPort),
	}

	if family, ok := mapIPFamilyToString[flow.FamilyType]; ok {
		packet.Family = family
	} else {
		klog.V(4).Info("Unknown IP family", "family", flow.FamilyType, "flow", flow)
		if flow.Forward.SrcIP.To4() != nil {
			packet.Family = v1.IPv4Protocol
		} else {
			packet.Family = v1.IPv6Protocol
		}
	}

	if protocol, ok := mapProtocolToString[flow.Forward.Protocol]; ok {
		packet.Proto = protocol
	} else {
		klog.V(4).Info("Unknown protocol", "protocol", flow.Forward.Protocol, "flow", flow)
		packet.Proto = v1.ProtocolTCP
	}

	return &packet
}

type conntrackFilter struct {
	flows sets.Set[string]
}

var _ netlink.CustomConntrackFilter = (*conntrackFilter)(nil)

func NewConntrackFilter(flows []*netlink.ConntrackFlow) *conntrackFilter {
	filter := &conntrackFilter{
		flows: sets.Set[string]{},
	}
	for _, flow := range flows {
		filter.flows.Insert(generateConntrackKey(flow))
	}
	return filter
}

func (f *conntrackFilter) MatchConntrackFlow(flow *netlink.ConntrackFlow) bool {
	if flow == nil || f.flows == nil {
		return false
	}

	key := generateConntrackKey(flow)
	return f.flows.Has(key)
}

// generateConntrackKey creates a unique key for a conntrack flow based on a hash
// of its forward-path tuple and IP family.
// The key is a SHA256 hash derived from the concatenation of:
// FamilyType, Forward.Protocol, Forward.SrcIP, Reverse.SrcIP, Forward.SrcPort,
// and Reverse.SrcPort.
func generateConntrackKey(flow *netlink.ConntrackFlow) string {
	hasher := sha256.New()

	// Sequentially write the fields to the hasher. The order is critical
	// for ensuring the hash is deterministic.
	// Write the IP family type (e.g., AF_INET for IPv4, AF_INET6 for IPv6).
	hasher.Write([]byte{flow.FamilyType})
	// Write the L4 protocol number (e.g., 6 for TCP, 17 for UDP).
	hasher.Write([]byte{flow.Forward.Protocol})
	// Write the source IP address. A net.IP is already a byte slice.
	hasher.Write(flow.Forward.SrcIP)
	// Write the destination IP address after NAT (if any).
	hasher.Write(flow.Reverse.SrcIP)
	// Write the source and destination ports. We use binary.BigEndian to
	// ensure a consistent byte order, regardless of the host machine's architecture.
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, flow.Forward.SrcPort)
	hasher.Write(portBuf)
	binary.BigEndian.PutUint16(portBuf, flow.Reverse.SrcPort)
	hasher.Write(portBuf)
	// Calculate the final hash sum.
	hashBytes := hasher.Sum(nil)
	// Return the hexadecimal representation of the hash as a string,
	return fmt.Sprintf("%x", hashBytes)
}
