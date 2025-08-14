package networkpolicy

import (
	"context"
	"net"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/klog/v2"
	"sigs.k8s.io/kube-network-policies/pkg/api"
	"sigs.k8s.io/kube-network-policies/pkg/network"
	npav1alpha1 "sigs.k8s.io/network-policy-api/apis/v1alpha1"
	banpinformers "sigs.k8s.io/network-policy-api/pkg/client/informers/externalversions/apis/v1alpha1"
	banplisters "sigs.k8s.io/network-policy-api/pkg/client/listers/apis/v1alpha1"
)

// BaselineAdminNetworkPolicy implements the PolicyEvaluator interface for the ANP API.
type BaselineAdminNetworkPolicy struct {
	banpLister banplisters.BaselineAdminNetworkPolicyLister
}

var _ PolicyEvaluator = &BaselineAdminNetworkPolicy{}

// NewAdminNetworkPolicy creates a new ANP implementation.
func NewBaselineAdminNetworkPolicy(banpInformer banpinformers.BaselineAdminNetworkPolicyInformer) *BaselineAdminNetworkPolicy {
	return &BaselineAdminNetworkPolicy{
		banpLister: banpInformer.Lister(),
	}
}

func (b *BaselineAdminNetworkPolicy) Name() string {
	return "BaselineAdminNetworkPolicy"
}

func (b *BaselineAdminNetworkPolicy) EvaluateIngress(ctx context.Context, p *network.Packet, srcPod, dstPod *api.PodInfo) (Verdict, error) {
	logger := klog.FromContext(ctx)

	allPolicies, err := b.banpLister.List(labels.Everything())
	if err != nil || len(allPolicies) == 0 {
		return VerdictNext, err
	}

	dstPodBaselineAdminNetworkPolices := getBaselineAdminNetworkPoliciesForPod(dstPod, allPolicies)
	if len(dstPodBaselineAdminNetworkPolices) == 0 {
		logger.V(2).Info("Ingress BaselineAdminNetworkPolicies does not apply")
		return VerdictNext, nil
	}
	ingressAction := b.evaluateBaselineAdminIngress(dstPodBaselineAdminNetworkPolices, srcPod, dstPod, p.SrcIP, p.SrcPort, p.Proto)
	logger.V(2).Info("Ingress BaselineAdminNetworkPolicies", "npolicies", len(dstPodBaselineAdminNetworkPolices), "action", ingressAction)

	switch ingressAction {
	case npav1alpha1.BaselineAdminNetworkPolicyRuleActionAllow:
		return VerdictAccept, nil
	case npav1alpha1.BaselineAdminNetworkPolicyRuleActionDeny:
		return VerdictDeny, nil
	default: // Pass
		return VerdictNext, nil
	}
}

func (b *BaselineAdminNetworkPolicy) EvaluateEgress(ctx context.Context, p *network.Packet, srcPod, dstPod *api.PodInfo) (Verdict, error) {
	logger := klog.FromContext(ctx)

	allPolicies, err := b.banpLister.List(labels.Everything())
	if err != nil || len(allPolicies) == 0 {
		logger.V(2).Info("Egress BaselineAdminNetworkPolicies does not apply")
		return VerdictNext, err
	}

	srcPodBaselineAdminNetworkPolices := getBaselineAdminNetworkPoliciesForPod(srcPod, allPolicies)
	egressAction := b.evaluateBaselineAdminEgress(srcPodBaselineAdminNetworkPolices, dstPod, p.DstIP, p.DstPort, p.Proto)
	logger.V(2).Info("Egress BaselineAdminNetworkPolicies", "npolicies", len(srcPodBaselineAdminNetworkPolices), "action", egressAction)

	switch egressAction {
	case npav1alpha1.BaselineAdminNetworkPolicyRuleActionAllow:
		return VerdictAccept, nil
	case npav1alpha1.BaselineAdminNetworkPolicyRuleActionDeny:
		return VerdictDeny, nil
	default: // Pass
		return VerdictNext, nil
	}
}

// getBaselineAdminNetworkPoliciesForPod filters a list of all BANPs and returns only those
// that apply to a given pod.
// A policy applies to a pod if the pod matches the policy's 'Subject' field.
func getBaselineAdminNetworkPoliciesForPod(pod *api.PodInfo, allPolicies []*npav1alpha1.BaselineAdminNetworkPolicy) []*npav1alpha1.BaselineAdminNetworkPolicy {
	if pod == nil {
		return nil
	}

	var result []*npav1alpha1.BaselineAdminNetworkPolicy
	for _, policy := range allPolicies {
		// A policy's subject can select pods in two ways: by their namespace, or by
		// a combination of namespace and pod labels.
		subject := policy.Spec.Subject
		matches := false
		if subject.Namespaces != nil && matchesSelector(subject.Namespaces, pod.Namespace.Labels) {
			matches = true
		}

		if !matches && subject.Pods != nil &&
			matchesSelector(&subject.Pods.NamespaceSelector, pod.Namespace.Labels) &&
			matchesSelector(&subject.Pods.PodSelector, pod.Labels) {
			matches = true
		}

		if matches {
			result = append(result, policy)
		}
	}

	return result
}

func (b *BaselineAdminNetworkPolicy) evaluateBaselineAdminEgress(adminNetworkPolices []*npav1alpha1.BaselineAdminNetworkPolicy, dstPod *api.PodInfo, ip net.IP, port int, protocol v1.Protocol) npav1alpha1.BaselineAdminNetworkPolicyRuleAction {
	for _, policy := range adminNetworkPolices {
		for _, rule := range policy.Spec.Egress {
			// Ports allows for matching traffic based on port and protocols.
			// This field is a list of destination ports for the outgoing egress traffic.
			// If Ports is not set then the rule does not filter traffic via port.
			if rule.Ports != nil {
				if !evaluateAdminNetworkPolicyPort(*rule.Ports, dstPod, port, protocol) {
					continue
				}
			}
			// To is the List of destinations whose traffic this rule applies to.
			// If any AdminNetworkPolicyEgressPeer matches the destination of outgoing
			// traffic then the specified action is applied.
			// This field must be defined and contain at least one item.
			for _, to := range rule.To {
				// Exactly one of the selector pointers must be set for a given peer. If a
				// consumer observes none of its fields are set, they must assume an unknown
				// option has been specified and fail closed.
				if to.Namespaces != nil && dstPod != nil {
					if matchesSelector(to.Namespaces, dstPod.Namespace.Labels) {
						return rule.Action
					}
				}

				if to.Pods != nil && dstPod != nil {
					if matchesSelector(&to.Pods.NamespaceSelector, dstPod.Namespace.Labels) &&
						matchesSelector(&to.Pods.PodSelector, dstPod.Labels) {
						return rule.Action
					}
				}

				if to.Nodes != nil && dstPod != nil {
					if matchesSelector(to.Nodes, dstPod.Node.Labels) {
						return rule.Action
					}
				}

				for _, network := range to.Networks {
					_, cidr, err := net.ParseCIDR(string(network))
					if err != nil { // this has been validated by the API
						continue
					}
					if cidr.Contains(ip) {
						return rule.Action
					}
				}
			}
		}
	}

	return npav1alpha1.BaselineAdminNetworkPolicyRuleActionAllow
}

func (b *BaselineAdminNetworkPolicy) evaluateBaselineAdminIngress(adminNetworkPolices []*npav1alpha1.BaselineAdminNetworkPolicy, srcPod, dstPod *api.PodInfo, ip net.IP, port int, protocol v1.Protocol) npav1alpha1.BaselineAdminNetworkPolicyRuleAction {
	// Ingress rules only apply if the source is a pod within the cluster.
	if srcPod == nil {
		return npav1alpha1.BaselineAdminNetworkPolicyRuleActionAllow
	}
	for _, policy := range adminNetworkPolices {
		for _, rule := range policy.Spec.Ingress {
			// If rule.Ports is specified, it must match the destination port.
			// If Ports is not set then the rule does not filter traffic via port.
			if rule.Ports != nil {
				if !evaluateAdminNetworkPolicyPort(*rule.Ports, dstPod, port, protocol) {
					continue
				}
			}
			// From is the list of sources whose traffic this rule applies to.
			// If any AdminNetworkPolicyIngressPeer matches the source of incoming traffic then the specified action is applied.
			// This field must be defined and contain at least one item.
			for _, from := range rule.From {
				// Exactly one of the selector pointers must be set for a given peer. If a
				// consumer observes none of its fields are set, they must assume an unknown
				// option has been specified and fail closed.
				if from.Namespaces != nil {
					if matchesSelector(from.Namespaces, srcPod.Namespace.Labels) {
						return rule.Action
					}
				}

				if from.Pods != nil {
					if matchesSelector(&from.Pods.NamespaceSelector, srcPod.Namespace.Labels) &&
						matchesSelector(&from.Pods.PodSelector, srcPod.Labels) {
						return rule.Action
					}
				}
			}

		}
	}

	return npav1alpha1.BaselineAdminNetworkPolicyRuleActionAllow
}
