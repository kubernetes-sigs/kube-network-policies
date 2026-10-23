// SPDX-License-Identifier: APACHE-2.0

package networkpolicy

import (
	"context"
	"fmt"
	"net"
	"strconv"

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

// VerdictRecord is the outcome of the evaluation of one packet.
type VerdictRecord struct {
	// Packet is a copy of the evaluated packet, not a pointer to it. The
	// caller of the engine owns the packet and the record is read by the
	// writer goroutine after the verdict, so a shared packet would make the
	// log depend on the caller never touching it again (swapping the tuple,
	// reusing the struct). The copy costs a memcpy per logged packet and
	// about 120 bytes per buffered record, and keeps the record correct
	// whatever the caller does next. The copy is shallow: SrcIP and DstIP
	// share their bytes with the packet, which no caller modifies in place.
	Packet network.Packet
	// SrcPod and DstPod are nil when the IP does not belong to a known Pod.
	SrcPod *api.PodInfo
	DstPod *api.PodInfo
	// Verdict is VerdictAccept or VerdictDeny.
	Verdict api.Verdict
	// Direction is the pipeline that produced the verdict and Evaluator the
	// name of the evaluator that produced it. A denied packet was denied by
	// that evaluator. An accepted packet was accepted by both pipelines, so
	// they refer to the ingress one, and they are empty when it accepted the
	// packet because no evaluator had a verdict for it.
	Direction Direction
	Evaluator string
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
	records chan VerdictRecord
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
		records: make(chan VerdictRecord, bufferSize),
	}
}

// Log hands over a record to be written, it never blocks.
func (l *VerdictLogger) Log(r VerdictRecord) {
	if !l.mode.logs(r.Verdict) {
		return
	}
	// The payload is not logged and it aliases the receive buffer of the
	// nfqueue, do not keep it alive until the record is written.
	r.Packet.Payload = nil
	select {
	case l.records <- r:
	default:
		verdictLogDropped.Inc()
	}
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

func (l *VerdictLogger) write(r VerdictRecord) {
	l.logger.Info("Packet verdict",
		"id", r.Packet.ID,
		"verdict", r.Verdict.String(),
		"family", r.Packet.Family,
		"protocol", r.Packet.Proto,
		"src", net.JoinHostPort(r.Packet.SrcIP.String(), strconv.Itoa(r.Packet.SrcPort)),
		"dst", net.JoinHostPort(r.Packet.DstIP.String(), strconv.Itoa(r.Packet.DstPort)),
		"srcPod", podKey(r.SrcPod),
		"dstPod", podKey(r.DstPod),
		"direction", r.Direction,
		"evaluator", r.Evaluator,
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
