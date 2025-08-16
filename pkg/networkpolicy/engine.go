// SPDX-License-Identifier: APACHE-2.0

package networkpolicy

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
	"sigs.k8s.io/kube-network-policies/pkg/api"
	"sigs.k8s.io/kube-network-policies/pkg/network"
)

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

// PodInfoProvider defines an interface for components that can provide PodInfo.
type PodInfoProvider interface {
	GetPodInfoByIP(podIP string) (*api.PodInfo, bool)
}

// DomainResolver provides an interface for resolving domain names to IP addresses.
type DomainResolver interface {
	ContainsIP(domain string, ip net.IP) bool
}

// EvaluatorFunc is the function signature for any logic that evaluates a packet.
type EvaluatorFunc func(ctx context.Context, p *network.Packet, srcPod, dstPod *api.PodInfo) (Verdict, error)

// Evaluator is a function that can determine a verdict for a packet.
type Evaluator struct {
	Name     string
	Evaluate EvaluatorFunc
}

// SyncFunc is a callback function that an evaluator can invoke to trigger
// a dataplane reconciliation.
type SyncFunc func()

// PolicyEvaluator is the complete interface for a policy plugin.
// It is responsible for both evaluating packets against its policies and
// providing the necessary configuration to the dataplane.
type PolicyEvaluator interface {
	// Name returns the identifier for this evaluator.
	Name() string
	// Ready returns true if the evaluator is initialized and ready to work.
	Ready() bool

	// EvaluateIngress/EvaluateEgress perform the runtime packet evaluation.
	EvaluateIngress(ctx context.Context, p *network.Packet, srcPod, dstPod *api.PodInfo) (Verdict, error)
	EvaluateEgress(ctx context.Context, p *network.Packet, srcPod, dstPod *api.PodInfo) (Verdict, error)

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

// PolicyEngine orchestrates network policy evaluation by running a fixed
// sequence of policy-specific evaluators.
type PolicyEngine struct {
	podInfoProvider PodInfoProvider
	evaluators      []PolicyEvaluator
}

// NewPolicyEngine creates a new engine with a predefined evaluation order.
func NewPolicyEngine(podInfoProvider PodInfoProvider, evaluators []PolicyEvaluator) *PolicyEngine {
	return &PolicyEngine{
		podInfoProvider: podInfoProvider,
		evaluators:      evaluators,
	}
}

// EvaluatePacket runs the full ingress and egress evaluation pipelines.
func (e *PolicyEngine) EvaluatePacket(ctx context.Context, packet *network.Packet) (bool, error) {
	logger := klog.FromContext(ctx)

	// Only run podInfoProvider once per packet to guarantee consistency
	// across the pipeline and for efficiency.
	srcPod, _ := e.podInfoProvider.GetPodInfoByIP(packet.SrcIP.String())
	dstPod, _ := e.podInfoProvider.GetPodInfoByIP(packet.DstIP.String())

	// 1. Evaluate Egress
	verdict, err := e.runEgressPipeline(ctx, packet, srcPod, dstPod)
	if err != nil {
		logger.Error(err, "Egress pipeline evaluation failed")
		return false, err
	}
	if verdict == VerdictDeny {
		logger.V(2).Info("Packet denied by egress policy")
		return false, nil
	}

	// 2. Evaluate Ingress
	verdict, err = e.runIngressPipeline(ctx, packet, srcPod, dstPod)
	if err != nil {
		logger.Error(err, "Ingress pipeline evaluation failed")
		return false, err
	}
	if verdict == VerdictDeny {
		logger.V(2).Info("Packet denied by ingress policy")
		return false, nil
	}

	logger.V(2).Info("Packet accepted by policy")
	return true, nil
}

// runEgressPipeline executes the sequence of egress evaluators.
func (e *PolicyEngine) runEgressPipeline(ctx context.Context, p *network.Packet, srcPod, dstPod *api.PodInfo) (Verdict, error) {
	for _, evaluator := range e.evaluators {
		verdict, err := evaluator.EvaluateEgress(ctx, p, srcPod, dstPod)
		if err != nil {
			return VerdictDeny, err
		}
		// Accept or Deny are final verdicts
		if verdict != VerdictNext {
			return verdict, nil
		}
	}
	return VerdictAccept, nil
}

// runIngressPipeline executes the sequence of ingress evaluators.
func (e *PolicyEngine) runIngressPipeline(ctx context.Context, p *network.Packet, srcPod, dstPod *api.PodInfo) (Verdict, error) {
	for _, evaluator := range e.evaluators {
		verdict, err := evaluator.EvaluateIngress(ctx, p, srcPod, dstPod)
		if err != nil {
			return VerdictDeny, err
		}
		// Accept or Deny are final verdicts
		if verdict != VerdictNext {
			return verdict, nil
		}
	}
	return VerdictAccept, nil
}

// SetDataplaneSyncCallbacks iterates through all evaluators and registers the
// dataplane's sync function with each one.
func (e *PolicyEngine) SetDataplaneSyncCallbacks(syncFn SyncFunc) {
	for _, evaluator := range e.evaluators {
		evaluator.SetDataplaneSyncCallback(syncFn)
	}
}

// Ready returns true if all evaluators are ready.
func (e *PolicyEngine) Ready() bool {
	for _, evaluator := range e.evaluators {
		if !evaluator.Ready() {
			return false
		}
	}
	return true
}

// GetManagedIPs aggregates the IPs and diversion signals from all registered evaluators.
// This is the single method the dataplane controller will call to get its configuration.
func (e *PolicyEngine) GetManagedIPs(ctx context.Context) (allIPs []netip.Addr, divertAll bool, err error) {
	ipSet := sets.New[netip.Addr]()

	for _, evaluator := range e.evaluators {
		ips, divert, err := evaluator.ManagedIPs(ctx)
		if err != nil {
			return nil, false, fmt.Errorf("failed to get managed IPs from evaluator %s: %w", evaluator.Name(), err)
		}

		// If any single evaluator requires diverting all traffic, the whole system must.
		if divert {
			return nil, true, nil
		}

		// Add the IPs from this evaluator to the global set to handle duplicates.
		for _, ip := range ips {
			ipSet.Insert(ip)
		}
	}

	return ipSet.UnsortedList(), false, nil
}
