package dataplane

import (
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	v1 "k8s.io/api/core/v1"
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
		klog.InfoS("Unknown IP family", "family", flow.FamilyType, "flow", flow)
		return nil
	}

	if protocol, ok := mapProtocolToString[flow.Forward.Protocol]; ok {
		packet.Proto = protocol
	} else {
		klog.InfoS("Unknown protocol", "protocol", flow.Forward.Protocol, "flow", flow)
		return nil
	}

	return &packet
}

// generateLabelMask creates a 16-byte (128-bit) mask with a single bit set at the
// specified bitIndex.
// If the bit index is out of the valid range [0, 127], it returns a 16-byte
// slice of all zeros.
// This function implements a Big Endia 128-bit layout. This means the
// most significant byte (containing bits 127-120) is at index 0 of the
// slice, and the least significant *byte* (containing bits 7-0) is at
// index 15.
func generateLabelMask(bitIndex int) []byte {
	labelMask := make([]byte, 16)
	if bitIndex < 0 || bitIndex > 127 {
		return labelMask
	}

	arrayIndex := len(labelMask) - (bitIndex / 8) - 1
	bitPos := uint(bitIndex % 8)
	mask := uint8(1) << bitPos
	labelMask[arrayIndex] = mask
	return labelMask
}

// clearLabelBit clears a specific bit in a 16-byte (128-bit) label and returns
// a new 16-byte slice with the modified label. The original slice (currentLabel)
// is not modified.
// If currentLabel is not 16 bytes long, it returns a new, empty 16-byte slice.
// If bitIndex is out of the valid range [0, 127], it returns a copy of the
// original label.
func clearLabelBit(currentLabel []byte, bitIndex int) []byte {
	newLabel := make([]byte, 16)
	if len(currentLabel) != 16 {
		return newLabel
	}

	copy(newLabel, currentLabel)
	if bitIndex < 0 || bitIndex > 127 {
		return newLabel
	}
	arrayIndex := len(newLabel) - (bitIndex / 8) - 1
	bitPos := uint(bitIndex % 8)
	zeroMask := ^(uint8(1) << bitPos)
	newLabel[arrayIndex] &= zeroMask
	return newLabel
}

// hasLabelBit reports whether the specified bit is set in a 16-byte (128-bit) big-endian label.
func hasLabelBit(currentLabel []byte, bitIndex int) bool {
	if len(currentLabel) != 16 || bitIndex < 0 || bitIndex > 127 {
		return false
	}
	arrayIndex := len(currentLabel) - (bitIndex / 8) - 1
	bitPos := uint(bitIndex % 8)
	return (currentLabel[arrayIndex] & (uint8(1) << bitPos)) != 0
}

// ipCTIsReply is IP_CT_IS_REPLY from enum ip_conntrack_info in
// include/uapi/linux/netfilter/nf_conntrack_common.h. The kernel sends this
// value in the NFQA_CT_INFO attribute when the queue is configured with
// NFQA_CFG_F_CONNTRACK.
//
//	IP_CT_ESTABLISHED       = 0
//	IP_CT_RELATED           = 1
//	IP_CT_NEW               = 2
//	IP_CT_IS_REPLY          = 3
//	IP_CT_ESTABLISHED_REPLY = IP_CT_ESTABLISHED + IP_CT_IS_REPLY = 3
//	IP_CT_RELATED_REPLY     = IP_CT_RELATED + IP_CT_IS_REPLY     = 4
//	IP_CT_NUMBER            = 5 (no NEW in the reply direction)
//	IP_CT_UNTRACKED         = 7
const ipCTIsReply uint32 = 3

// isReply reports whether the packet flows in the reply direction of its
// conntrack entry. It mirrors the kernel's CTINFO2DIR() from
// include/uapi/linux/netfilter/nf_conntrack_tuple_common.h:
//
//	#define CTINFO2DIR(ctinfo) ((ctinfo) >= IP_CT_IS_REPLY ? IP_CT_DIR_REPLY : IP_CT_DIR_ORIGINAL)
func isReply(ctInfo *uint32) bool {
	return ctInfo != nil && *ctInfo >= ipCTIsReply
}
