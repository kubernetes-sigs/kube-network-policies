// SPDX-License-Identifier: APACHE-2.0

package networkpolicy

import (
	"context"
	"net"
	"sort"

	"k8s.io/klog/v2"
	"sigs.k8s.io/kube-network-policies/pkg/api"
	"sigs.k8s.io/kube-network-policies/pkg/network"
)

// PodInfoProvider defines an interface for components that can provide PodInfo.
type PodInfoProvider interface {
	// GetPodInfoByIP retrieves information about a pod by its IP address.
	GetPodInfoByIP(podIP string) (*api.PodInfo, bool)
}

// DomainResolver provides an interface for resolving domain names to IP addresses.
type DomainResolver interface {
	// ContainsIP checks if the given IP is associated with the domain.
	// The domain can be a specific domain or a wildcard.
	ContainsIP(domain string, ip net.IP) bool
}

// Verdict represents the outcome of a packet evaluation.
type Verdict int

const (
	// VerdictAccept is a final verdict that allows the packet, halting the pipeline.
	// On the contrary of Netfilter ACCEPT meaning, that means let's the packet through.
	VerdictAccept Verdict = iota
	// VerdictDeny is a final verdict that denies the packet, halting the pipeline.
	VerdictDeny
	// VerdictNext continues to the next evaluator in the pipeline, same as the Netfilter
	// ACCEPT meaning.
	VerdictNext
)

// EvaluatorFunc is the function signature for any logic that evaluates a packet.
type EvaluatorFunc func(ctx context.Context, p *network.Packet) (Verdict, error)

// Evaluator wraps an evaluation function with a priority and a name.
type Evaluator struct {
	Priority int
	Name     string
	Evaluate EvaluatorFunc
}

// Pipeline holds and runs a series of evaluators in order of priority.
type Pipeline struct {
	evaluators []Evaluator
}

// NewPipeline creates and returns a new, empty pipeline.
func NewPipeline(evaluators ...Evaluator) *Pipeline {
	pipeline := &Pipeline{
		evaluators: make([]Evaluator, 0),
	}
	for _, evaluator := range evaluators {
		pipeline.AddEvaluator(evaluator)
	}
	return pipeline
}

// AddEvaluator adds a new evaluator to the pipeline and re-sorts the evaluators
// based on their priority. If multiple evaluators have the same priority, they
// will remain in the order in which they were added to the pipeline.
func (p *Pipeline) AddEvaluator(evaluator Evaluator) {
	p.evaluators = append(p.evaluators, evaluator)
	sort.SliceStable(p.evaluators, func(i, j int) bool {
		return p.evaluators[i].Priority < p.evaluators[j].Priority
	})
}

// Run executes the pipeline for a given packet. It processes each evaluator
// in priority order until a final verdict (Allow or Deny) is reached, or the
// context is canceled.
func (p *Pipeline) Run(ctx context.Context, packet *network.Packet) (bool, error) {
	logger := klog.FromContext(ctx)
	for _, evaluator := range p.evaluators {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		default:
			verdict, err := evaluator.Evaluate(ctx, packet)
			if err != nil {
				logger.Error(err, "evaluator returned an error", "evaluator", evaluator.Name)
				return false, err // Returning the error to be handled by the caller.
			}

			switch verdict {
			case VerdictAccept:
				logger.V(2).Info("packet allowed by evaluator", "evaluator", evaluator.Name)
				return true, nil
			case VerdictDeny:
				logger.V(2).Info("packet denied by evaluator", "evaluator", evaluator.Name)
				return false, nil
			case VerdictNext:
				// Continue to the next evaluator.
				logger.V(2).Info("packet continue to the next evaluator", "evaluator", evaluator.Name)
				continue
			}
		}
	}
	// If the pipeline completes without a final verdict, default to allowing the packet.
	// TODO: check if we want to make this configurable.
	logger.V(2).Info("packet accepted by all evaluators")
	return true, nil
}
