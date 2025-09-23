// SPDX-License-Identifier: APACHE-2.0

package networkpolicy

import (
	"cmp"
	"context"
	"net"
	"net/netip"
	"slices"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	"sigs.k8s.io/kube-network-policies/pkg/api"
	"sigs.k8s.io/kube-network-policies/pkg/network"
	"sigs.k8s.io/kube-network-policies/pkg/networkpolicy"
	npav1alpha2 "sigs.k8s.io/network-policy-api/apis/v1alpha2"
	cnpinformers "sigs.k8s.io/network-policy-api/pkg/client/informers/externalversions/apis/v1alpha2"
	cnplisters "sigs.k8s.io/network-policy-api/pkg/client/listers/apis/v1alpha2"
)

// ClusterNetworkPolicy implements the PolicyEvaluator interface for the CNP API.
type ClusterNetworkPolicy struct {
	tier           npav1alpha2.Tier
	cnpLister      cnplisters.ClusterNetworkPolicyLister
	cnpSynced      cache.InformerSynced
	domainResolver api.DomainResolver
}

var _ api.PolicyEvaluator = &ClusterNetworkPolicy{}

// NewClusterNetworkPolicy creates a new CNP implementation.
func NewClusterNetworkPolicy(tier npav1alpha2.Tier, cnpInformer cnpinformers.ClusterNetworkPolicyInformer, domainResolver api.DomainResolver) *ClusterNetworkPolicy {
	return &ClusterNetworkPolicy{
		tier:           tier,
		cnpLister:      cnpInformer.Lister(),
		cnpSynced:      cnpInformer.Informer().HasSynced,
		domainResolver: domainResolver,
	}
}

func (c *ClusterNetworkPolicy) Name() string {
	return "ClusterNetworkPolicy" + string(c.tier)
}

func (c *ClusterNetworkPolicy) Ready() bool {
	return c.cnpSynced()
}

func (c *ClusterNetworkPolicy) SetDataplaneSyncCallback(syncFn api.SyncFunc) {
	// No-op for ClusterNetworkPolicy as it doesn't directly control dataplane rules.
	// The controller will handle syncing based on policy changes.
}

func (c *ClusterNetworkPolicy) ManagedIPs(ctx context.Context) ([]netip.Addr, bool, error) {
	// divert all traffic to user space to evaluate all traffic to ensure that the correct
	// BaselineAdminNetworkPolicies are applied.
	return nil, true, nil
}

// EvaluateIngress evaluates ingress rules for the evaluator's specific tier.
func (c *ClusterNetworkPolicy) EvaluateIngress(ctx context.Context, p *network.Packet, srcPod, dstPod *api.PodInfo) (api.Verdict, error) {
	logger := klog.FromContext(ctx)

	policies, err := c.getPoliciesForPod(dstPod)
	if err != nil || len(policies) == 0 {
		return api.VerdictNext, err
	}

	action := c.evaluateClusterIngress(policies, srcPod, dstPod, p.DstPort, p.Proto)
	logger.V(2).Info("Ingress CNP evaluation", "tier", c.tier, "npolicies", len(policies), "action", action)

	return actionToVerdict(action), nil
}

// EvaluateEgress evaluates egress rules for the evaluator's specific tier.
func (c *ClusterNetworkPolicy) EvaluateEgress(ctx context.Context, p *network.Packet, srcPod, dstPod *api.PodInfo) (api.Verdict, error) {
	logger := klog.FromContext(ctx)

	policies, err := c.getPoliciesForPod(srcPod)
	if err != nil || len(policies) == 0 {
		return api.VerdictNext, err
	}

	action := c.evaluateClusterEgress(policies, dstPod, p.DstIP, p.DstPort, p.Proto)
	logger.V(2).Info("Egress CNP evaluation", "tier", c.tier, "npolicies", len(policies), "action", action)

	return actionToVerdict(action), nil
}

// getPoliciesForPod filters policies from the lister that match the pod and the evaluator's tier.
func (c *ClusterNetworkPolicy) getPoliciesForPod(pod *api.PodInfo) ([]*npav1alpha2.ClusterNetworkPolicy, error) {
	if pod == nil {
		return nil, nil
	}

	allPolicies, err := c.cnpLister.List(labels.Everything())
	if err != nil {
		return nil, err
	}

	var result []*npav1alpha2.ClusterNetworkPolicy
	for _, policy := range allPolicies {
		// Filter by the tier this evaluator instance is responsible for.
		if policy.Spec.Tier != c.tier {
			continue
		}

		subject := policy.Spec.Subject
		matches := false
		if subject.Namespaces != nil && networkpolicy.MatchesSelector(subject.Namespaces, pod.Namespace.Labels) {
			matches = true
		}
		if !matches && subject.Pods != nil &&
			networkpolicy.MatchesSelector(&subject.Pods.NamespaceSelector, pod.Namespace.Labels) &&
			networkpolicy.MatchesSelector(&subject.Pods.PodSelector, pod.Labels) {
			matches = true
		}

		if matches {
			result = append(result, policy)
		}
	}

	// Sort by priority and then by name for deterministic evaluation.
	slices.SortFunc(result, func(a, b *npav1alpha2.ClusterNetworkPolicy) int {
		if n := cmp.Compare(a.Spec.Priority, b.Spec.Priority); n != 0 {
			return n
		}
		return cmp.Compare(a.Name, b.Name)
	})
	return result, nil
}

// evaluateClusterEgress evaluates a list of egress policies for a traffic flow.
func (c *ClusterNetworkPolicy) evaluateClusterEgress(
	policies []*npav1alpha2.ClusterNetworkPolicy,
	dstPod *api.PodInfo,
	dstIP net.IP,
	dstPort int,
	protocol v1.Protocol,
) npav1alpha2.ClusterNetworkPolicyRuleAction {
	for _, policy := range policies {
		for _, rule := range policy.Spec.Egress {
			if rule.Ports != nil {
				if !evaluateClusterNetworkPolicyPort(*rule.Ports, dstPod, dstPort, protocol) {
					continue
				}
			}
			for _, to := range rule.To {
				if to.Namespaces != nil && dstPod != nil && networkpolicy.MatchesSelector(to.Namespaces, dstPod.Namespace.Labels) {
					return rule.Action
				}

				if to.Pods != nil && dstPod != nil &&
					networkpolicy.MatchesSelector(&to.Pods.NamespaceSelector, dstPod.Namespace.Labels) &&
					networkpolicy.MatchesSelector(&to.Pods.PodSelector, dstPod.Labels) {
					return rule.Action
				}

				if to.Nodes != nil && dstPod != nil && networkpolicy.MatchesSelector(to.Nodes, dstPod.Node.Labels) {
					return rule.Action
				}

				for _, network := range to.Networks {
					_, cidr, err := net.ParseCIDR(string(network))
					if err != nil {
						continue
					}
					if cidr.Contains(dstIP) {
						return rule.Action
					}
				}
				for _, domain := range to.DomainNames {
					if c.domainResolver != nil && c.domainResolver.ContainsIP(string(domain), dstIP) {
						return rule.Action
					}
				}
			}
		}
	}
	// Per CNP spec, if no rule matches, the default action is 'Pass'.
	return npav1alpha2.ClusterNetworkPolicyRuleActionPass
}

// evaluateClusterIngress evaluates a list of ingress policies for a traffic flow.
func (c *ClusterNetworkPolicy) evaluateClusterIngress(
	policies []*npav1alpha2.ClusterNetworkPolicy,
	srcPod, dstPod *api.PodInfo,
	dstPort int,
	protocol v1.Protocol,
) npav1alpha2.ClusterNetworkPolicyRuleAction {
	if srcPod == nil {
		return npav1alpha2.ClusterNetworkPolicyRuleActionPass
	}
	for _, policy := range policies {
		for _, rule := range policy.Spec.Ingress {
			if rule.Ports != nil {
				if !evaluateClusterNetworkPolicyPort(*rule.Ports, dstPod, dstPort, protocol) {
					continue
				}
			}
			for _, from := range rule.From {
				if from.Namespaces != nil && networkpolicy.MatchesSelector(from.Namespaces, srcPod.Namespace.Labels) {
					return rule.Action
				}

				if from.Pods != nil &&
					networkpolicy.MatchesSelector(&from.Pods.NamespaceSelector, srcPod.Namespace.Labels) &&
					networkpolicy.MatchesSelector(&from.Pods.PodSelector, srcPod.Labels) {
					return rule.Action
				}
			}
		}
	}
	return npav1alpha2.ClusterNetworkPolicyRuleActionPass
}

// evaluateClusterNetworkPolicyPort checks if a specific port and protocol match any port selectors.
func evaluateClusterNetworkPolicyPort(
	policyPorts []npav1alpha2.ClusterNetworkPolicyPort,
	pod *api.PodInfo,
	port int,
	protocol v1.Protocol,
) bool {
	if len(policyPorts) == 0 {
		return true
	}

	for _, policyPort := range policyPorts {
		if policyPort.PortNumber != nil &&
			policyPort.PortNumber.Port == int32(port) &&
			policyPort.PortNumber.Protocol == protocol {
			return true
		}

		if policyPort.NamedPort != nil {
			if pod == nil {
				continue
			}
			for _, containerPort := range pod.ContainerPorts {
				if containerPort.Name == *policyPort.NamedPort && v1.Protocol(containerPort.Protocol) == protocol && containerPort.Port == int32(port) {
					return true
				}
			}
		}

		if policyPort.PortRange != nil &&
			policyPort.PortRange.Protocol == protocol &&
			policyPort.PortRange.Start <= int32(port) &&
			policyPort.PortRange.End >= int32(port) {
			return true
		}
	}
	return false
}

// actionToVerdict translates a CNP action into an internal Verdict.
func actionToVerdict(action npav1alpha2.ClusterNetworkPolicyRuleAction) api.Verdict {
	switch action {
	case npav1alpha2.ClusterNetworkPolicyRuleActionAccept:
		return api.VerdictAccept
	case npav1alpha2.ClusterNetworkPolicyRuleActionDeny:
		return api.VerdictDeny
	case npav1alpha2.ClusterNetworkPolicyRuleActionPass:
		return api.VerdictNext
	default:
		// Default to a "pass" behavior is safest if the action is unknown or empty.
		return api.VerdictNext
	}
}
