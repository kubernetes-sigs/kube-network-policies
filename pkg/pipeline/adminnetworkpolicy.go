package pipeline

import (
	"cmp"
	"context"
	"net"
	"slices"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog/v2"
	"sigs.k8s.io/kube-network-policies/pkg/api"
	"sigs.k8s.io/kube-network-policies/pkg/network"
	npav1alpha1 "sigs.k8s.io/network-policy-api/apis/v1alpha1"
	anplisters "sigs.k8s.io/network-policy-api/pkg/client/listers/apis/v1alpha1"
)

// namespaceSelector return true if the namespace selector matches the pod
func namespaceSelector(selector *metav1.LabelSelector, pod *api.PodInfo) bool {
	nsSelector, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		return false
	}

	return nsSelector.Matches(labels.Set(pod.Namespace.Labels))
}

// podSelector return true if the pod selector matches the pod
func podSelector(selector *metav1.LabelSelector, pod *api.PodInfo) bool {
	podSelector, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		return false
	}
	return podSelector.Matches(labels.Set(pod.Labels))
}

// nodeSelector return true if the node selector matches the pod
func nodeSelector(selector *metav1.LabelSelector, pod *api.PodInfo) bool {
	nodeSelector, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		return false
	}
	return nodeSelector.Matches(labels.Set(pod.Node.Labels))
}

// NewAdminNetworkPolicyEvaluator creates a new pipeline evaluator for AdminNetworkPolicies.
func NewAdminNetworkPolicyEvaluator(
	podInfoGetter PodByIPGetter,
	anpLister anplisters.AdminNetworkPolicyLister,
	nsLister corelisters.NamespaceLister,
) Evaluator {
	return Evaluator{
		Priority: 10,
		Name:     "AdminNetworkPolicy",
		Evaluate: func(ctx context.Context, p *network.Packet) (Verdict, error) {
			logger := klog.FromContext(ctx)
			srcPod, srcPodFound := podInfoGetter(p.SrcIP.String())
			dstPod, dstPodFound := podInfoGetter(p.DstIP.String())

			verdict := VerdictNext
			// Egress Evaluation
			if dstPodFound {
				allPolicies, err := anpLister.List(labels.Everything())
				if err != nil {
					return VerdictNext, err
				}
				srcPodAdminNetworkPolices := getAdminNetworkPoliciesForPod(srcPod, allPolicies)
				action := evaluateAdminEgress(srcPodAdminNetworkPolices, dstPod, p.DstIP, p.DstPort, p.Proto)
				logger.V(2).Info("Egress AdminNetworkPolicies", "npolicies", len(srcPodAdminNetworkPolices), "action", action)

				switch action {
				case npav1alpha1.AdminNetworkPolicyRuleActionDeny:
					return VerdictDeny, nil
				case npav1alpha1.AdminNetworkPolicyRuleActionAllow:
					verdict = VerdictAccept
					break
				case npav1alpha1.AdminNetworkPolicyRuleActionPass:
					break
				}
			}

			// Ingress Evaluation
			if srcPodFound {
				allPolicies, err := anpLister.List(labels.Everything())
				if err != nil {
					return VerdictNext, err
				}
				dstPodAdminNetworkPolices := getAdminNetworkPoliciesForPod(dstPod, allPolicies)
				action := evaluateAdminIngress(dstPodAdminNetworkPolices, srcPod, p.DstPort, p.Proto)
				logger.V(2).Info("Ingress AdminNetworkPolicies", "npolicies", len(dstPodAdminNetworkPolices), "action", action)

				switch action {
				case npav1alpha1.AdminNetworkPolicyRuleActionDeny:
					return VerdictDeny, nil
				case npav1alpha1.AdminNetworkPolicyRuleActionAllow:
					return VerdictAccept, nil
				case npav1alpha1.AdminNetworkPolicyRuleActionPass:
					break
				}
			}

			return verdict, nil
		},
	}
}

func getAdminNetworkPoliciesForPod(pod *api.PodInfo, networkPolicies []*npav1alpha1.AdminNetworkPolicy) []*npav1alpha1.AdminNetworkPolicy {
	if pod == nil {
		return nil
	}

	result := []*npav1alpha1.AdminNetworkPolicy{}
	for _, policy := range networkPolicies {
		if policy.Spec.Subject.Namespaces != nil &&
			namespaceSelector(policy.Spec.Subject.Namespaces, pod) {
			result = append(result, policy)
		}

		if policy.Spec.Subject.Pods != nil &&
			namespaceSelector(&policy.Spec.Subject.Pods.NamespaceSelector, pod) &&
			podSelector(&policy.Spec.Subject.Pods.PodSelector, pod) {
			klog.InfoS("Pod match AdminNetworkPolicy", "policy", policy.Name)
			result = append(result, policy)
		}
	}
	// Rules with lower priority values have higher precedence
	slices.SortFunc(result, func(a, b *npav1alpha1.AdminNetworkPolicy) int {
		if n := cmp.Compare(a.Spec.Priority, b.Spec.Priority); n != 0 {
			return n
		}
		// If priorities are equal, order by name
		return cmp.Compare(a.Name, b.Name)
	})
	return result
}

// evaluateAdminEgress assume the list of network policies is ordered
func evaluateAdminEgress(adminNetworkPolices []*npav1alpha1.AdminNetworkPolicy, pod *api.PodInfo, ip net.IP, port int, protocol v1.Protocol) npav1alpha1.AdminNetworkPolicyRuleAction {
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
					if namespaceSelector(to.Namespaces, pod) {
						return rule.Action
					}
				}

				if to.Pods != nil && pod != nil {
					if namespaceSelector(&to.Pods.NamespaceSelector, pod) &&
						podSelector(&to.Pods.PodSelector, pod) {
						return rule.Action
					}
				}

				if to.Nodes != nil && pod != nil {
					if nodeSelector(to.Nodes, pod) {
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

				// TODO DNS
				// for _, domain := range to.DomainNames {
				//	if c.domainCache.ContainsIP(string(domain), ip) {
				//		return rule.Action
				//	}
				// }
			}
		}
	}

	return npav1alpha1.AdminNetworkPolicyRuleActionPass
}

// evaluateAdminIngress assume the list of network policies is ordered
func evaluateAdminIngress(adminNetworkPolices []*npav1alpha1.AdminNetworkPolicy, pod *api.PodInfo, port int, protocol v1.Protocol) npav1alpha1.AdminNetworkPolicyRuleAction {
	// Ingress rules only apply to pods
	if pod == nil {
		return npav1alpha1.AdminNetworkPolicyRuleActionPass
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
					if namespaceSelector(from.Namespaces, pod) {
						return rule.Action
					}
				}

				if from.Pods != nil {
					if namespaceSelector(&from.Pods.NamespaceSelector, pod) &&
						podSelector(&from.Pods.PodSelector, pod) {
						return rule.Action
					}
				}
			}

		}
	}

	return npav1alpha1.AdminNetworkPolicyRuleActionPass
}

func evaluateAdminNetworkPolicyPort(networkPolicyPorts []npav1alpha1.AdminNetworkPolicyPort, pod *api.PodInfo, port int, protocol v1.Protocol) bool {
	// AdminNetworkPolicyPort describes how to select network ports on pod(s).
	// Exactly one field must be set.
	if len(networkPolicyPorts) == 0 {
		return true
	}

	for _, policyPort := range networkPolicyPorts {
		// Port number
		if policyPort.PortNumber != nil &&
			policyPort.PortNumber.Port == int32(port) &&
			policyPort.PortNumber.Protocol == protocol {
			return true
		}

		// Named Port
		if policyPort.NamedPort != nil {
			if pod == nil {
				continue
			}
			for _, p := range pod.ContainerPorts {
				if p.Name == *policyPort.NamedPort {
					return true
				}
			}
		}

		// Port range
		if policyPort.PortRange != nil &&
			policyPort.PortRange.Protocol == protocol &&
			policyPort.PortRange.Start <= int32(port) &&
			policyPort.PortRange.End >= int32(port) {
			return true
		}

	}
	return false
}
