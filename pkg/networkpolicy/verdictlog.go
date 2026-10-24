// SPDX-License-Identifier: APACHE-2.0

package networkpolicy

import (
	"context"
	"fmt"
	"net/netip"

	v1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"

	"sigs.k8s.io/kube-network-policies/pkg/api"
	"sigs.k8s.io/kube-network-policies/pkg/network"
)

// VerdictLogMode selects the verdicts written by the VerdictLogger.
type VerdictLogMode string

const (
	// VerdictLogNone disables the verdict log.
	VerdictLogNone VerdictLogMode = "none"
	// VerdictLogDeny writes the denied packets.
	VerdictLogDeny VerdictLogMode = "deny"
	// VerdictLogAll writes the denied and the accepted packets.
	VerdictLogAll VerdictLogMode = "all"
)

// String implements flag.Value.
func (m *VerdictLogMode) String() string {
	return string(*m)
}

// Set implements flag.Value.
func (m *VerdictLogMode) Set(s string) error {
	switch VerdictLogMode(s) {
	case VerdictLogNone, VerdictLogDeny, VerdictLogAll:
		*m = VerdictLogMode(s)
		return nil
	}
	return fmt.Errorf("must be one of %q, %q or %q", VerdictLogNone, VerdictLogDeny, VerdictLogAll)
}

// logs returns true when the mode writes verdicts of this kind.
func (m VerdictLogMode) logs(verdict api.Verdict) bool {
	switch m {
	case VerdictLogAll:
		return true
	case VerdictLogDeny:
		return verdict == api.VerdictDeny
	}
	return false
}

// Direction is the pipeline that evaluated a packet.
type Direction string

const (
	DirectionEgress  Direction = "egress"
	DirectionIngress Direction = "ingress"
)

// verdictRecord is what the writer needs from the evaluation of one packet.
// It shares no memory with the packet: the caller of the engine owns the
// packet and may reuse it after the verdict, and the record is read later by
// the writer goroutine.
type verdictRecord struct {
	id     uint32
	family v1.IPFamily
	proto  v1.Protocol
	src    netip.AddrPort
	dst    netip.AddrPort
	// srcPod and dstPod are nil when the IP does not belong to a known Pod.
	srcPod *api.PodInfo
	dstPod *api.PodInfo
	// verdict is VerdictAccept or VerdictDeny.
	verdict api.Verdict
	// direction is the pipeline that produced the verdict and evaluator the
	// name of the evaluator that produced it. A denied packet was denied by
	// that evaluator. An accepted packet was accepted by both pipelines, so
	// they refer to the ingress one, and they are empty when it accepted the
	// packet because no evaluator had a verdict for it.
	direction Direction
	evaluator string
}

// verdictLogBufferSize is the number of records kept while the log
// destination is slower than the verdicts. The kernel keeps at most 1024
// packets waiting for a verdict, so the buffer absorbs several of those
// bursts before any record is dropped.
const verdictLogBufferSize = 4096

// VerdictLogger writes the verdicts of the PolicyEngine out of the packet
// processing path. The engine hands the records over through a buffer and
// a goroutine writes them, so a slow log destination delays the records and
// never the verdicts. When the buffer is full the records are dropped and
// counted in the kube_network_policies_verdict_log_dropped metric.
type VerdictLogger struct {
	mode    VerdictLogMode
	logger  klog.Logger
	records chan verdictRecord
}

// NewVerdictLogger creates a VerdictLogger that writes the verdicts selected
// by mode with logger. Run must be called for the records to be written.
func NewVerdictLogger(logger klog.Logger, mode VerdictLogMode) *VerdictLogger {
	return newVerdictLogger(logger, mode, verdictLogBufferSize)
}

func newVerdictLogger(logger klog.Logger, mode VerdictLogMode, bufferSize int) *VerdictLogger {
	registerMetrics()
	return &VerdictLogger{
		mode:    mode,
		logger:  logger,
		records: make(chan verdictRecord, bufferSize),
	}
}

// Log hands over the verdict of packet to be written, it never blocks.
// srcPod and dstPod are nil when the IP does not belong to a known Pod,
// direction and evaluator are empty when no evaluator produced the verdict.
func (l *VerdictLogger) Log(packet *network.Packet, srcPod, dstPod *api.PodInfo, verdict api.Verdict, direction Direction, evaluator string) {
	if !l.mode.logs(verdict) {
		return
	}
	r := verdictRecord{
		id:        packet.ID,
		family:    packet.Family,
		proto:     packet.Proto,
		src:       addrPort(packet.SrcIP, packet.SrcPort),
		dst:       addrPort(packet.DstIP, packet.DstPort),
		srcPod:    srcPod,
		dstPod:    dstPod,
		verdict:   verdict,
		direction: direction,
		evaluator: evaluator,
	}
	select {
	case l.records <- r:
	default:
		verdictLogDropped.Inc()
	}
}

// addrPort copies ip and port into a value that does not alias ip.
func addrPort(ip []byte, port int) netip.AddrPort {
	addr, _ := netip.AddrFromSlice(ip)
	return netip.AddrPortFrom(addr.Unmap(), uint16(port))
}

// Run writes the records until ctx is done, then it writes the records
// already buffered and returns.
func (l *VerdictLogger) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			for {
				select {
				case r := <-l.records:
					l.write(r)
				default:
					return
				}
			}
		case r := <-l.records:
			l.write(r)
		}
	}
}

func (l *VerdictLogger) write(r verdictRecord) {
	l.logger.Info("Packet verdict",
		"id", r.id,
		"verdict", r.verdict.String(),
		"family", r.family,
		"protocol", r.proto,
		"src", r.src.String(),
		"dst", r.dst.String(),
		"srcPod", podKey(r.srcPod),
		"dstPod", podKey(r.dstPod),
		"direction", r.direction,
		"evaluator", r.evaluator,
	)
}

// podKey returns the namespace/name of the Pod, or "external" when the IP
// does not belong to a known Pod, as the LoggingPolicy does.
func podKey(pod *api.PodInfo) string {
	if pod == nil {
		return "external"
	}
	return pod.Namespace.Name + "/" + pod.Name
}
