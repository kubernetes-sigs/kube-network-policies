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
	// verdictLogger receives the verdicts, nil when they are not logged.
	verdictLogger *VerdictLogger
}

// NewPolicyEngine creates a new engine with a predefined evaluation order.
func NewPolicyEngine(podInfoProvider api.PodInfoProvider, evaluators []api.PolicyEvaluator) *PolicyEngine {
	registerMetrics()
	return &PolicyEngine{
		podInfoProvider: podInfoProvider,
		evaluators:      evaluators,
	}
}

// SetVerdictLogger makes the engine log its verdicts with l. It must be
// called before the engine starts evaluating packets.
func (e *PolicyEngine) SetVerdictLogger(l *VerdictLogger) {
	e.verdictLogger = l
}

// EvaluatePacket runs the full ingress and egress evaluation pipelines.
func (e *PolicyEngine) EvaluatePacket(ctx context.Context, packet *network.Packet) (bool, error) {
	logger := klog.FromContext(ctx).WithValues("id", packet.ID)
	ctx = klog.NewContext(ctx, logger)

	// Only run podInfoProvider once per packet to guarantee consistency
	// across the pipeline and for efficiency.
	srcPod, _ := e.podInfoProvider.GetPodInfoByIP(packet.SrcIP.String())
	dstPod, _ := e.podInfoProvider.GetPodInfoByIP(packet.DstIP.String())
	if srcPod == nil {
		unresolvedIPCounter.WithLabelValues("source").Inc()
	}
	if dstPod == nil {
		unresolvedIPCounter.WithLabelValues("destination").Inc()
	}

	// 1. Evaluate Egress
	verdict, evaluator, err := e.runEgressPipeline(ctx, packet, srcPod, dstPod)
	if err != nil {
		logger.Error(err, "Egress pipeline evaluation failed")
		return false, err
	}
	if verdict == api.VerdictDeny {
		logger.V(4).Info("Packet denied by egress policy")
		e.logVerdict(packet, srcPod, dstPod, verdict, DirectionEgress, evaluator)
		return false, nil
	}

	// 2. Evaluate Ingress
	verdict, evaluator, err = e.runIngressPipeline(ctx, packet, srcPod, dstPod)
	if err != nil {
		logger.Error(err, "Ingress pipeline evaluation failed")
		return false, err
	}
	if verdict == api.VerdictDeny {
		logger.V(4).Info("Packet denied by ingress policy")
		e.logVerdict(packet, srcPod, dstPod, verdict, DirectionIngress, evaluator)
		return false, nil
	}

	logger.V(4).Info("Packet accepted by policy")
	e.logVerdict(packet, srcPod, dstPod, verdict, DirectionIngress, evaluator)
	return true, nil
}

// logVerdict hands the verdict over to the verdict logger, if any. The
// evaluator is nil when the pipeline accepted the packet by default.
func (e *PolicyEngine) logVerdict(packet *network.Packet, srcPod, dstPod *api.PodInfo, verdict api.Verdict, direction Direction, evaluator api.PolicyEvaluator) {
	if e.verdictLogger == nil {
		return
	}
	name := ""
	if evaluator != nil {
		name = evaluator.Name()
	} else {
		direction = ""
	}
	e.verdictLogger.Log(packet, srcPod, dstPod, verdict, direction, name)
}

// runEgressPipeline executes the sequence of egress evaluators and returns
// the final verdict with the evaluator that produced it, or VerdictAccept and
// nil when no evaluator had a final verdict.
func (e *PolicyEngine) runEgressPipeline(ctx context.Context, p *network.Packet, srcPod, dstPod *api.PodInfo) (api.Verdict, api.PolicyEvaluator, error) {
	for _, evaluator := range e.evaluators {
		verdict, err := evaluator.EvaluateEgress(ctx, p, srcPod, dstPod)
		if err != nil {
			return api.VerdictDeny, evaluator, err
		}
		// Accept or Deny are final verdicts
		if verdict != api.VerdictNext {
			return verdict, evaluator, nil
		}
	}
	return api.VerdictAccept, nil, nil
}

// runIngressPipeline executes the sequence of ingress evaluators and returns
// the final verdict with the evaluator that produced it, or VerdictAccept and
// nil when no evaluator had a final verdict.
func (e *PolicyEngine) runIngressPipeline(ctx context.Context, p *network.Packet, srcPod, dstPod *api.PodInfo) (api.Verdict, api.PolicyEvaluator, error) {
	for _, evaluator := range e.evaluators {
		verdict, err := evaluator.EvaluateIngress(ctx, p, srcPod, dstPod)
		if err != nil {
			return api.VerdictDeny, evaluator, err
		}
		// Accept or Deny are final verdicts
		if verdict != api.VerdictNext {
			return verdict, evaluator, nil
		}
	}
	return api.VerdictAccept, nil, nil
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
