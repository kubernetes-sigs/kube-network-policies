package pipeline

import (
	"context"
	"net"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/klog/v2"
	"sigs.k8s.io/kube-network-policies/pkg/api"
	"sigs.k8s.io/kube-network-policies/pkg/network"
	npav1alpha1 "sigs.k8s.io/network-policy-api/apis/v1alpha1"
	"sigs.k8s.io/network-policy-api/pkg/client/informers/externalversions/apis/v1alpha1"
)

// NewBaselineAdminNetworkPolicyEvaluator creates a new pipeline evaluator for BaselineAdminNetworkPolicies.
func NewBaselineAdminNetworkPolicyEvaluator(
	podInfoProvider PodInfoProvider,
	banpInformer v1alpha1.BaselineAdminNetworkPolicyInformer,
) Evaluator {

	banpLister := banpInformer.Lister()

	return Evaluator{
		Priority: 100,
		Name:     "BaselineAdminNetworkPolicy",
		Evaluate: func(ctx context.Context, p *network.Packet) (Verdict, error) {
			logger := klog.FromContext(ctx)
			srcPod, srcPodFound := podInfoProvider.GetPodInfoByIP(p.SrcIP.String())
			dstPod, dstPodFound := podInfoProvider.GetPodInfoByIP(p.DstIP.String())

			allPolicies, err := banpLister.List(labels.Everything())
			if err != nil {
				return VerdictNext, err
			}
			if len(allPolicies) == 0 {
				return VerdictNext, nil
			}
			// 1. Evaluate Egress policies for the source pod.
			// These policies dictate whether the source pod is allowed to send traffic.
			if srcPodFound {
				srcPodBaselineAdminNetworkPolices := getBaselineAdminNetworkPoliciesForPod(srcPod, allPolicies)
				egressAction := evaluateBaselineAdminEgress(srcPodBaselineAdminNetworkPolices, dstPod, p.DstIP, p.DstPort, p.Proto)
				logger.V(2).Info("Egress BaselineAdminNetworkPolicies", "npolicies", len(srcPodBaselineAdminNetworkPolices), "action", egressAction)
				if egressAction == npav1alpha1.BaselineAdminNetworkPolicyRuleActionDeny {
					return VerdictDeny, nil
				}
			}

			// 2. Evaluate Ingress policies for the destination pod.
			// These policies dictate whether the destination pod is allowed to receive traffic.
			if dstPodFound {
				dstPodBaselineAdminNetworkPolices := getBaselineAdminNetworkPoliciesForPod(dstPod, allPolicies)
				ingressAction := evaluateBaselineAdminIngress(dstPodBaselineAdminNetworkPolices, srcPod, p.SrcIP, p.SrcPort, p.Proto)
				logger.V(2).Info("Ingress BaselineAdminNetworkPolicies", "npolicies", len(dstPodBaselineAdminNetworkPolices), "action", ingressAction)
				// Egress has to be Allow or Pass if we are here.
				if ingressAction == npav1alpha1.BaselineAdminNetworkPolicyRuleActionDeny {
					return VerdictDeny, nil
				}
				if ingressAction == npav1alpha1.BaselineAdminNetworkPolicyRuleActionAllow {
					return VerdictAccept, nil
				}
			}

			return VerdictNext, nil
		},
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

func evaluateBaselineAdminEgress(adminNetworkPolices []*npav1alpha1.BaselineAdminNetworkPolicy, pod *api.PodInfo, ip net.IP, port int, protocol v1.Protocol) npav1alpha1.BaselineAdminNetworkPolicyRuleAction {
	for _, policy := range adminNetworkPolices {
		for _, rule := range policy.Spec.Egress {
			// Ports allows for matching traffic based on port and protocols.
			// This field is a list of destination ports for the outgoing egress traffic.
			// If Ports is not set then the rule does not filter traffic via port.
			if rule.Ports != nil {
				if !evaluateAdminNetworkPolicyPort(*rule.Ports, pod, port, protocol) {
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
				if to.Namespaces != nil && pod != nil {
					if matchesSelector(to.Namespaces, pod.Namespace.Labels) {
						return rule.Action
					}
				}

				if to.Pods != nil && pod != nil {
					if matchesSelector(&to.Pods.NamespaceSelector, pod.Namespace.Labels) &&
						matchesSelector(&to.Pods.PodSelector, pod.Labels) {
						return rule.Action
					}
				}

				if to.Nodes != nil && pod != nil {
					if matchesSelector(to.Nodes, pod.Node.Labels) {
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

func evaluateBaselineAdminIngress(adminNetworkPolices []*npav1alpha1.BaselineAdminNetworkPolicy, pod *api.PodInfo, ip net.IP, port int, protocol v1.Protocol) npav1alpha1.BaselineAdminNetworkPolicyRuleAction {
	// Ingress rules only apply to pods
	if pod == nil {
		return npav1alpha1.BaselineAdminNetworkPolicyRuleActionAllow
	}
	for _, policy := range adminNetworkPolices {
		// Ingress is the list of Ingress rules to be applied to the selected pods. A total of 100 rules will be allowed in each ANP instance. The relative precedence of ingress rules within a single ANP object (all of which share the priority) will be determined by the order in which the rule is written. Thus, a rule that appears at the top of the ingress rules would take the highest precedence.
		// ANPs with no ingress rules do not affect ingress traffic.
		for _, rule := range policy.Spec.Ingress {
			// Ports allows for matching traffic based on port and protocols.
			// This field is a list of ports which should be matched on the pods selected for this policy
			// i.e the subject of the policy. So it matches on the destination port for the ingress traffic.
			// If Ports is not set then the rule does not filter traffic via port.
			if rule.Ports != nil {
				if !evaluateAdminNetworkPolicyPort(*rule.Ports, pod, port, protocol) {
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
					if matchesSelector(from.Namespaces, pod.Namespace.Labels) {
						return rule.Action
					}
				}

				if from.Pods != nil {
					if matchesSelector(&from.Pods.NamespaceSelector, pod.Namespace.Labels) &&
						matchesSelector(&from.Pods.PodSelector, pod.Labels) {
						return rule.Action
					}
				}
			}

		}
	}

	return npav1alpha1.BaselineAdminNetworkPolicyRuleActionAllow
}
