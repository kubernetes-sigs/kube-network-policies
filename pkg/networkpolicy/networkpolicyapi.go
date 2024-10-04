package networkpolicy

import (
	"cmp"
	"context"
	"net"
	"slices"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/klog/v2"
	npav1alpha1 "sigs.k8s.io/network-policy-api/apis/v1alpha1"
)

func (c *Controller) evaluateAdminEgress(adminNetworkPolices []*npav1alpha1.AdminNetworkPolicy, pod *v1.Pod, ip net.IP, port int, protocol v1.Protocol) npav1alpha1.AdminNetworkPolicyRuleAction {
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
					if c.namespaceSelector(to.Namespaces, pod) {
						return rule.Action
					}
				}

				if to.Pods != nil && pod != nil {
					if c.namespaceSelector(&to.Pods.NamespaceSelector, pod) &&
						podSelector(&to.Pods.PodSelector, pod) {
						return rule.Action
					}
				}

				if to.Nodes != nil && pod != nil {
					if c.nodeSelector(to.Nodes, pod) {
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

	return npav1alpha1.AdminNetworkPolicyRuleActionPass
}

func (c *Controller) evaluateAdminIngress(adminNetworkPolices []*npav1alpha1.AdminNetworkPolicy, pod *v1.Pod, port int, protocol v1.Protocol) npav1alpha1.AdminNetworkPolicyRuleAction {
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
					if c.namespaceSelector(from.Namespaces, pod) {
						return rule.Action
					}
				}

				if from.Pods != nil {
					if c.namespaceSelector(&from.Pods.NamespaceSelector, pod) &&
						podSelector(&from.Pods.PodSelector, pod) {
						return rule.Action
					}
				}
			}

		}
	}

	return npav1alpha1.AdminNetworkPolicyRuleActionPass
}

// namespaceSelector return true if the namespace selector matches the pod
func (c *Controller) namespaceSelector(selector *metav1.LabelSelector, pod *v1.Pod) bool {
	nsSelector, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		return false
	}

	namespaces, err := c.namespaceLister.List(nsSelector)
	if err != nil {
		return false
	}

	for _, ns := range namespaces {
		if pod.Namespace == ns.Name {
			return true
		}
	}
	return false
}

// podSelector return true if the pod selector matches the pod
func podSelector(selector *metav1.LabelSelector, pod *v1.Pod) bool {
	podSelector, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		return false
	}
	return podSelector.Matches(labels.Set(pod.Labels))
}

// nodeSelector return true if the node selector matches the pod
func (c *Controller) nodeSelector(selector *metav1.LabelSelector, pod *v1.Pod) bool {
	nodeSelector, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		return false
	}
	nodes, err := c.nodeLister.List(nodeSelector)
	if err != nil {
		return false
	}
	for _, node := range nodes {
		if pod.Spec.NodeName == node.Name {
			return true
		}
	}
	return false
}

// getAdminNetworkPoliciesForPod returns the list of Admin Network Policies matching the Pod
// The list is ordered by priority, from higher to lower.
func (c *Controller) getAdminNetworkPoliciesForPod(ctx context.Context, pod *v1.Pod) []*npav1alpha1.AdminNetworkPolicy {
	if pod == nil {
		return nil
	}
	logger := klog.FromContext(ctx)
	tlogger := logger.V(2)
	if tlogger.Enabled() {
		tlogger = tlogger.WithValues("pod", pod.Name, "namespace", pod.Namespace)
	}
	// Get all the network policies that affect this pod
	networkPolices, err := c.adminNetworkPolicyLister.List(labels.Everything())
	if err != nil {
		logger.Info("getAdminNetworkPoliciesForPod", "error", err)
		return nil
	}

	result := []*npav1alpha1.AdminNetworkPolicy{}
	for _, policy := range networkPolices {
		if policy.Spec.Subject.Namespaces != nil &&
			c.namespaceSelector(policy.Spec.Subject.Namespaces, pod) {
			tlogger.Info("Pod match AdminNetworkPolicy", "policy", policy.Name)
			result = append(result, policy)
		}

		if policy.Spec.Subject.Pods != nil &&
			c.namespaceSelector(&policy.Spec.Subject.Pods.NamespaceSelector, pod) &&
			podSelector(&policy.Spec.Subject.Pods.PodSelector, pod) {
			tlogger.Info("Pod match AdminNetworkPolicy", "policy", policy.Name)
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

func evaluateAdminNetworkPolicyPort(networkPolicyPorts []npav1alpha1.AdminNetworkPolicyPort, pod *v1.Pod, port int, protocol v1.Protocol) bool {
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
			for _, container := range pod.Spec.Containers {
				for _, p := range container.Ports {
					if p.Name == *policyPort.NamedPort {
						return true
					}
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

// getBaselineAdminNetworkPoliciesForPod returns the list of Baseline Admin Network Policies matching the Pod
// The list is ordered by priority, from higher to lower.
func (c *Controller) getBaselineAdminNetworkPoliciesForPod(ctx context.Context, pod *v1.Pod) []*npav1alpha1.BaselineAdminNetworkPolicy {
	if pod == nil {
		return nil
	}
	logger := klog.FromContext(ctx)
	tlogger := logger.V(2)
	if tlogger.Enabled() {
		tlogger = tlogger.WithValues("pod", pod.Name, "namespace", pod.Namespace)
	}
	// Get all the network policies that affect this pod
	networkPolices, err := c.baselineAdminNetworkPolicyLister.List(labels.Everything())
	if err != nil {
		logger.Info("getBaselineAdminNetworkPoliciesForPod", "error", err)
		return nil
	}

	result := []*npav1alpha1.BaselineAdminNetworkPolicy{}
	for _, policy := range networkPolices {
		if policy.Spec.Subject.Namespaces != nil &&
			c.namespaceSelector(policy.Spec.Subject.Namespaces, pod) {
			tlogger.Info("Pod match AdminNetworkPolicy", "policy", policy.Name)
			result = append(result, policy)
		}

		if policy.Spec.Subject.Pods != nil &&
			c.namespaceSelector(&policy.Spec.Subject.Pods.NamespaceSelector, pod) &&
			podSelector(&policy.Spec.Subject.Pods.PodSelector, pod) {
			tlogger.Info("Pod match AdminNetworkPolicy", "policy", policy.Name)
			result = append(result, policy)
		}
	}
	return result
}

func (c *Controller) evaluateBaselineAdminEgress(adminNetworkPolices []*npav1alpha1.BaselineAdminNetworkPolicy, pod *v1.Pod, ip net.IP, port int, protocol v1.Protocol) npav1alpha1.BaselineAdminNetworkPolicyRuleAction {
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
					if c.namespaceSelector(to.Namespaces, pod) {
						return rule.Action
					}
				}

				if to.Pods != nil && pod != nil {
					if c.namespaceSelector(&to.Pods.NamespaceSelector, pod) &&
						podSelector(&to.Pods.PodSelector, pod) {
						return rule.Action
					}
				}

				if to.Nodes != nil && pod != nil {
					if c.nodeSelector(to.Nodes, pod) {
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

func (c *Controller) evaluateBaselineAdminIngress(adminNetworkPolices []*npav1alpha1.BaselineAdminNetworkPolicy, pod *v1.Pod, port int, protocol v1.Protocol) npav1alpha1.BaselineAdminNetworkPolicyRuleAction {
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
					if c.namespaceSelector(from.Namespaces, pod) {
						return rule.Action
					}
				}

				if from.Pods != nil {
					if c.namespaceSelector(&from.Pods.NamespaceSelector, pod) &&
						podSelector(&from.Pods.PodSelector, pod) {
						return rule.Action
					}
				}
			}

		}
	}

	return npav1alpha1.BaselineAdminNetworkPolicyRuleActionAllow
}
