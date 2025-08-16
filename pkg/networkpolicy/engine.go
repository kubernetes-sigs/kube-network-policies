// SPDX-License-Identifier: APACHE-2.0

package networkpolicy

import (
	"context"
	"fmt"
	"net/netip"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
	"sigs.k8s.io/kube-network-policies/pkg/api"
	"sigs.k8s.io/kube-network-policies/pkg/network"
)

// EvaluatorFunc is the function signature for any logic that evaluates a packet.
type EvaluatorFunc func(ctx context.Context, p *network.Packet, srcPod, dstPod *api.PodInfo) (api.Verdict, error)

// Evaluator is a function that can determine a verdict for a packet.
type Evaluator struct {
	Name     string
	Evaluate EvaluatorFunc
}

// PolicyEngine orchestrates network policy evaluation by running a fixed
// sequence of policy-specific evaluators.
type PolicyEngine struct {
	podInfoProvider api.PodInfoProvider
	evaluators      []api.PolicyEvaluator
}

// NewPolicyEngine creates a new engine with a predefined evaluation order.
func NewPolicyEngine(podInfoProvider api.PodInfoProvider, evaluators []api.PolicyEvaluator) *PolicyEngine {
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
	if verdict == api.VerdictDeny {
		logger.V(2).Info("Packet denied by egress policy")
		return false, nil
	}

	// 2. Evaluate Ingress
	verdict, err = e.runIngressPipeline(ctx, packet, srcPod, dstPod)
	if err != nil {
		logger.Error(err, "Ingress pipeline evaluation failed")
		return false, err
	}
	if verdict == api.VerdictDeny {
		logger.V(2).Info("Packet denied by ingress policy")
		return false, nil
	}

	logger.V(2).Info("Packet accepted by policy")
	return true, nil
}

// runEgressPipeline executes the sequence of egress evaluators.
func (e *PolicyEngine) runEgressPipeline(ctx context.Context, p *network.Packet, srcPod, dstPod *api.PodInfo) (api.Verdict, error) {
	for _, evaluator := range e.evaluators {
		verdict, err := evaluator.EvaluateEgress(ctx, p, srcPod, dstPod)
		if err != nil {
			return api.VerdictDeny, err
		}
		// Accept or Deny are final verdicts
		if verdict != api.VerdictNext {
			return verdict, nil
		}
	}
	return api.VerdictAccept, nil
}

// runIngressPipeline executes the sequence of ingress evaluators.
func (e *PolicyEngine) runIngressPipeline(ctx context.Context, p *network.Packet, srcPod, dstPod *api.PodInfo) (api.Verdict, error) {
	for _, evaluator := range e.evaluators {
		verdict, err := evaluator.EvaluateIngress(ctx, p, srcPod, dstPod)
		if err != nil {
			return api.VerdictDeny, err
		}
		// Accept or Deny are final verdicts
		if verdict != api.VerdictNext {
			return verdict, nil
		}
	}
	return api.VerdictAccept, nil
}

// SetDataplaneSyncCallbacks iterates through all evaluators and registers the
// dataplane's sync function with each one.
func (e *PolicyEngine) SetDataplaneSyncCallbacks(syncFn api.SyncFunc) {
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
