// SPDX-License-Identifier: APACHE-2.0

package networkpolicy

import (
	"context"
	"net"

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

// PolicyEvaluator represents a collection of evaluators for a single policy type.
type PolicyEvaluator interface {
	Name() string
	EvaluateIngress(ctx context.Context, p *network.Packet, srcPod, dstPod *api.PodInfo) (Verdict, error)
	EvaluateEgress(ctx context.Context, p *network.Packet, srcPod, dstPod *api.PodInfo) (Verdict, error)
}

// PolicyEngine orchestrates network policy evaluation by running a fixed
// sequence of policy-specific evaluators.
type PolicyEngine struct {
	podInfoProvider PodInfoProvider
	evaluators      []PolicyEvaluator
}

// NewPolicyEngine creates a new engine with a predefined evaluation order.
func NewPolicyEngine(podInfoProvider PodInfoProvider, evaluators ...PolicyEvaluator) *PolicyEngine {
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
