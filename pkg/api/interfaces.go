package api

import (
	"context"
	"net"
	"net/netip"

	"sigs.k8s.io/kube-network-policies/pkg/network"
)

// PodInfoProvider defines an interface for components that can provide PodInfo.
type PodInfoProvider interface {
	GetPodInfoByIP(podIP string) (*PodInfo, bool)
}

// DomainResolver provides an interface for resolving domain names to IP addresses.
type DomainResolver interface {
	ContainsIP(domain string, ip net.IP) bool
}

// SyncFunc is a callback function that an evaluator can invoke to trigger
// a dataplane reconciliation.
type SyncFunc func()

// Verdict represents the outcome of a packet evaluation.
type Verdict int

const (
	// VerdictAccept allows the packet. In a directional pipeline, this means
	// the packet is allowed for that stage.
	VerdictAccept Verdict = iota
	// VerdictDeny denies the packet. This is a final decision for that direction.
	VerdictDeny
	// VerdictNext continues to the next evaluator in the pipeline.
	VerdictNext
)

// PolicyEvaluator is the complete interface for a policy plugin.
// It is responsible for both evaluating packets against its policies and
// providing the necessary configuration to the dataplane.
type PolicyEvaluator interface {
	// Name returns the identifier for this evaluator.
	Name() string
	// Ready returns true if the evaluator is initialized and ready to work.
	Ready() bool

	// EvaluateIngress/EvaluateEgress perform the runtime packet evaluation.
	EvaluateIngress(ctx context.Context, p *network.Packet, srcPod, dstPod *PodInfo) (Verdict, error)
	EvaluateEgress(ctx context.Context, p *network.Packet, srcPod, dstPod *PodInfo) (Verdict, error)

	// SetDataplaneSyncCallback allows the dataplane to provide a callback function.
	// The evaluator MUST call this function whenever its state changes in a way
	// that requires the dataplane rules to be re-synced.
	SetDataplaneSyncCallback(syncFn SyncFunc)

	// ManagedIPs returns the set of Pod IPs that this policy evaluator manages.
	// The dataplane uses this to build optimized nftables sets.
	// It can also return 'divertAll = true' to signal that all traffic
	// must be sent to the nfqueue, disabling the IP set optimization.
	ManagedIPs(ctx context.Context) (ips []netip.Addr, divertAll bool, err error)
}
