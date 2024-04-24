package networkpolicy

import (
	"fmt"
	"net"

	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/klog/v2"
)

func (c *Controller) getNetworkPoliciesForPod(pod *v1.Pod) []*networkingv1.NetworkPolicy {
	if pod == nil {
		return nil
	}
	// Get all the network policies that affect this pod
	networkPolices, err := c.networkpolicyLister.NetworkPolicies(pod.Namespace).List(labels.Everything())
	if err != nil {
		return nil
	}
	result := []*networkingv1.NetworkPolicy{}
	for _, policy := range networkPolices {
		// podSelector selects the pods to which this NetworkPolicy object applies.
		// The array of ingress rules is applied to any pods selected by this field.
		// Multiple network policies can select the same set of pods. In this case,
		// the ingress rules for each are combined additively.
		// This field is NOT optional and follows standard label selector semantics.
		// An empty podSelector matches all pods in this namespace.
		podSelector, err := metav1.LabelSelectorAsSelector(&policy.Spec.PodSelector)
		if err != nil {
			klog.Infof("error parsing PodSelector: %v", err)
			continue
		}
		// networkPolicy does not select the pod try the next network policy
		if podSelector.Matches(labels.Set(pod.Labels)) {
			result = append(result, policy)
		}
	}
	return result
}

func (c *Controller) acceptNetworkPolicy(p packet) bool {
	srcIP := p.srcIP
	srcPod := c.getPodAssignedToIP(srcIP.String())
	srcPort := p.srcPort
	dstIP := p.dstIP
	dstPod := c.getPodAssignedToIP(dstIP.String())
	dstPort := p.dstPort
	protocol := p.proto
	srcPodNetworkPolices := c.getNetworkPoliciesForPod(srcPod)
	dstPodNetworkPolices := c.getNetworkPoliciesForPod(dstPod)

	msg := fmt.Sprintf("checking packet %s", p.String())
	if srcPod != nil {
		msg += fmt.Sprintf("\nSrcPod (%s/%s): %d NetworkPolicy", srcPod.Name, srcPod.Namespace, len(srcPodNetworkPolices))
	}
	if dstPod != nil {
		msg += fmt.Sprintf("\nDstPod (%s/%s): %d NetworkPolicy", dstPod.Name, dstPod.Namespace, len(dstPodNetworkPolices))
	}
	klog.V(2).Infof("%s", msg)

	// For a connection from a source pod to a destination pod to be allowed,
	// both the egress policy on the source pod and the ingress policy on the
	// destination pod need to allow the connection.
	// If either side does not allow the connection, it will not happen.

	// This is the first packet originated from srcPod so we need to check:
	// 1. srcPod egress is accepted
	// 2. dstPod ingress is accepted
	return c.evaluator(srcPodNetworkPolices, networkingv1.PolicyTypeEgress, srcPod, srcIP, srcPort, dstPod, dstIP, dstPort, protocol) &&
		c.evaluator(dstPodNetworkPolices, networkingv1.PolicyTypeIngress, dstPod, dstIP, dstPort, srcPod, srcIP, srcPort, protocol)
}

// validator obtains a verdict for network policies that applies to a src Pod in the direction
// passed as parameter
func (c *Controller) evaluator(
	networkPolicies []*networkingv1.NetworkPolicy, networkPolictType networkingv1.PolicyType,
	srcPod *v1.Pod, srcIP net.IP, srcPort int, dstPod *v1.Pod, dstIP net.IP, dstPort int, proto v1.Protocol) bool {

	// no network policies implies allow all by default
	if len(networkPolicies) == 0 {
		return true
	}

	// no network policies matching the Pod allows all
	verdict := true
	for _, netpol := range networkPolicies {
		for _, policyType := range netpol.Spec.PolicyTypes {
			// only evaluate one direction
			if policyType != networkPolictType {
				continue
			}

			if policyType == networkingv1.PolicyTypeEgress {
				// egress is a list of egress rules to be applied to the selected pods. Outgoing traffic
				// is allowed if there are no NetworkPolicies selecting the pod (and cluster policy
				// otherwise allows the traffic), OR if the traffic matches at least one egress rule
				// across all of the NetworkPolicy objects whose podSelector matches the pod. If
				// this field is empty then this NetworkPolicy limits all outgoing traffic (and serves
				// solely to ensure that the pods it selects are isolated by default).

				// if there is at least one network policy matching the Pod it defaults to deny
				verdict = false
				if netpol.Spec.Egress == nil {
					klog.V(2).Infof("Pod %s/%s has limited all egress traffic by NetworkPolicy %s/%s", srcPod.Name, srcPod.Namespace, netpol.Name, netpol.Namespace)
					continue
				}
				// This evaluator only evaluates one policyType, if it matches then traffic is allowed
				if c.evaluateEgress(netpol.Namespace, netpol.Spec.Egress, srcPod, dstPod, dstIP, dstPort, proto) {
					return true
				}
			}

			if policyType == networkingv1.PolicyTypeIngress {
				// ingress is a list of ingress rules to be applied to the selected pods.
				// Traffic is allowed to a pod if there are no NetworkPolicies selecting the pod
				// (and cluster policy otherwise allows the traffic), OR if the traffic source is
				// the pod's local node, OR if the traffic matches at least one ingress rule
				// across all of the NetworkPolicy objects whose podSelector matches the pod. If
				// this field is empty then this NetworkPolicy does not allow any traffic (and serves
				// solely to ensure that the pods it selects are isolated by default)

				// if there is at least one network policy matching the Pod it defaults to deny
				verdict = false
				if netpol.Spec.Ingress == nil {
					klog.V(2).Infof("Pod %s/%s has limited all ingress traffic by NetworkPolicy %s/%s", dstPod.Name, dstPod.Namespace, netpol.Name, netpol.Namespace)
					continue
				}
				// This evaluator only evaluates one policyType, if it matches then traffic is allowed
				if c.evaluateIngress(netpol.Namespace, netpol.Spec.Ingress, srcPod, srcPort, dstPod, dstIP, proto) {
					return true
				}
			}
		}
	}

	return verdict
}

func (c *Controller) evaluateIngress(netpolNamespace string, ingressRules []networkingv1.NetworkPolicyIngressRule, srcPod *v1.Pod, srcPort int, dstPod *v1.Pod, dstIP net.IP, proto v1.Protocol) bool {
	// assume srcPod and ingressRules are not nil
	if len(ingressRules) == 0 {
		klog.V(2).Infof("Pod %s/%s has allowed all egress traffic", srcPod.Name, srcPod.Namespace)
		return true
	}

	for _, rule := range ingressRules {
		// Evaluate if Port is accessible in the specified Pod
		if !c.evaluatePorts(rule.Ports, srcPod, srcPort, proto) {
			klog.V(2).Infof("Pod %s/%s is not allowed to be connected on port %d", srcPod.Name, srcPod.Namespace, srcPort)
			continue
		}

		// from is a list of sources which should be able to access the pods selected for this rule.
		// Items in this list are combined using a logical OR operation. If this field is
		// empty or missing, this rule matches all sources (traffic not restricted by
		// source). If this field is present and contains at least one item, this rule
		// allows traffic only if the traffic matches at least one item in the from list.
		if len(rule.From) == 0 {
			klog.V(2).Infof("Pod %s/%s is allowed to connect from any destination", srcPod.Name, srcPod.Namespace)
			return true
		}
		for _, peer := range rule.From {
			// IPBlock describes a particular CIDR (Ex. "192.168.1.0/24","2001:db8::/64") that is allowed
			// to the pods matched by a NetworkPolicySpec's podSelector. The except entry describes CIDRs
			// that should not be included within this rule.
			if peer.IPBlock != nil {
				if c.evaluateIPBlocks(peer.IPBlock, dstIP) {
					klog.V(2).Infof("Pod %s/%s is not accessible from %s", srcPod.Name, srcPod.Namespace, dstIP)
					return true
				}
				continue
			}

			// traffic coming from external does not match selectors
			if dstPod == nil {
				continue
			}

			if peer.NamespaceSelector != nil || peer.PodSelector != nil {
				if c.evaluateSelectors(peer.PodSelector, peer.NamespaceSelector, dstPod, netpolNamespace) {
					klog.V(2).Infof("Pod %s/%s is accessible from Pod %s/%s because match selectors", srcPod.Name, srcPod.Namespace, dstPod.Name, dstPod.Namespace)
					return true
				}
			}
		}
	}
	return false
}

func (c *Controller) evaluateEgress(netpolNamespace string, egressRules []networkingv1.NetworkPolicyEgressRule, srcPod *v1.Pod, dstPod *v1.Pod, dstIP net.IP, dstPort int, proto v1.Protocol) bool {
	if len(egressRules) == 0 {
		klog.V(2).Infof("Pod %s/%s has allowed all egress traffic", srcPod.Name, srcPod.Namespace)
		return true
	}

	for _, rule := range egressRules {
		// Evaluate if Pod is allowed to connect to dstPort
		if !c.evaluatePorts(rule.Ports, dstPod, dstPort, proto) {
			klog.V(2).Infof("Pod %s/%s is not allowed to connect to port %d", srcPod.Name, srcPod.Namespace, dstPort)
			continue
		}
		// to is a list of destinations for outgoing traffic of pods selected for this rule.
		// Items in this list are combined using a logical OR operation. If this field is
		// empty or missing, this rule matches all destinations (traffic not restricted by
		// destination). If this field is present and contains at least one item, this rule
		// allows traffic only if the traffic matches at least one item in the to list.
		if len(rule.To) == 0 {
			klog.V(2).Infof("Pod %s/%s is allowed to connect to any destination", srcPod.Name, srcPod.Namespace)
			return true
		}
		for _, peer := range rule.To {
			// IPBlock describes a particular CIDR (Ex. "192.168.1.0/24","2001:db8::/64") that is allowed
			// to the pods matched by a NetworkPolicySpec's podSelector. The except entry describes CIDRs
			// that should not be included within this rule.
			if peer.IPBlock != nil {
				if c.evaluateIPBlocks(peer.IPBlock, dstIP) {
					klog.V(2).Infof("Pod %s/%s is allowed to connect to %s", srcPod.Name, srcPod.Namespace, dstIP)
					return true
				}
				continue
			}

			// NamespaceSelector and PodSelector only apply to destination Pods
			if dstPod == nil {
				continue
			}

			if peer.NamespaceSelector != nil || peer.PodSelector != nil {
				if c.evaluateSelectors(peer.PodSelector, peer.NamespaceSelector, dstPod, netpolNamespace) {
					klog.V(2).Infof("Pod %s/%s is allowed to connect because of Pod and Namespace selectors", srcPod.Name, srcPod.Namespace)
					return true
				}
			}
		}
	}
	return false
}

func (c *Controller) evaluateSelectors(peerPodSelector *metav1.LabelSelector, peerNSSelector *metav1.LabelSelector, pod *v1.Pod, policyNs string) bool {
	// avoid panics
	if pod == nil {
		return true
	}

	// podSelector is a label selector which selects pods. This field follows standard label
	// selector semantics; if present but empty, it selects all pods.
	// If namespaceSelector is also set, then the NetworkPolicyPeer as a whole selects
	// the pods matching podSelector in the Namespaces selected by NamespaceSelector.
	if peerPodSelector != nil {
		podSelector, err := metav1.LabelSelectorAsSelector(peerPodSelector)
		if err != nil {
			klog.Infof("Accepting packet, error: %v", err)
			return true
		}
		// networkPolicy does not selects the pod
		if !podSelector.Matches(labels.Set(pod.Labels)) {
			return false
		}
		// if peerNSSelector selects the pods matching podSelector in the policy's own namespace
		if peerNSSelector == nil {
			return pod.Namespace == policyNs
		}
	}
	// namespaceSelector selects namespaces using cluster-scoped labels. This field follows
	// standard label selector semantics; if present but empty, it selects all namespaces.

	// If podSelector is also set, then the NetworkPolicyPeer as a whole selects
	// the pods matching podSelector in the namespaces selected by namespaceSelector.
	// Otherwise it selects all pods in the namespaces selected by namespaceSelector.
	if peerNSSelector != nil {
		// if present but empty, it selects all namespaces.
		if len(peerNSSelector.MatchLabels)+len(peerNSSelector.MatchExpressions) == 0 {
			return true
		}

		nsSelector, err := metav1.LabelSelectorAsSelector(peerNSSelector)
		if err != nil {
			klog.Infof("Accepting packet, error: %v", err)
			return true
		}

		namespaces, err := c.namespaceLister.List(nsSelector)
		if err != nil {
			klog.Infof("Accepting packet, error: %v", err)
			return true
		}
		for _, ns := range namespaces {
			if pod.Namespace == ns.Name {
				return true
			}
		}
		return false
	}
	// at least podSelector or nsSelector is guaranteed to be not nil
	// it should have returned before reaching this point
	return true
}

func (c *Controller) evaluateIPBlocks(ipBlock *networkingv1.IPBlock, ip net.IP) bool {
	if ipBlock == nil {
		return true
	}

	_, cidr, err := net.ParseCIDR(ipBlock.CIDR)
	if err != nil { // this has been validated by the API
		return true
	}

	if !cidr.Contains(ip) {
		return false
	}

	for _, except := range ipBlock.Except {
		_, cidr, err := net.ParseCIDR(except)
		if err != nil { // this has been validated by the API
			return true
		}
		if cidr.Contains(ip) {
			return false
		}
	}
	// it matched the cidr and didn't match the exceptions
	return true
}

func (c *Controller) evaluatePorts(networkPolicyPorts []networkingv1.NetworkPolicyPort, pod *v1.Pod, port int, protocol v1.Protocol) bool {
	// ports is a list of ports,  each item in this list is combined using a logical OR.
	// If this field is empty or missing, this rule matches all ports (traffic not restricted by port).
	// If this field is present and contains at least one item, then this rule allows
	// traffic only if the traffic matches at least one port in the list.
	if len(networkPolicyPorts) == 0 {
		return true
	}

	for _, policyPort := range networkPolicyPorts {
		if protocol != *policyPort.Protocol {
			continue
		}
		// matches all ports
		if policyPort.Port == nil {
			return true
		}
		if port == policyPort.Port.IntValue() {
			return true
		}
		if pod != nil && policyPort.Port.StrVal != "" {
			for _, container := range pod.Spec.Containers {
				for _, p := range container.Ports {
					if p.Name == policyPort.Port.StrVal &&
						p.ContainerPort == int32(port) &&
						p.Protocol == protocol {
						return true
					}
				}
			}
		}
		// endPort indicates that the range of ports from port to endPort if set, inclusive,
		// should be allowed by the policy. This field cannot be defined if the port field
		// is not defined or if the port field is defined as a named (string) port.
		// The endPort must be equal or greater than port.
		if policyPort.EndPort == nil {
			continue
		}
		if port > policyPort.Port.IntValue() && int32(port) <= *policyPort.EndPort {
			return true
		}
	}
	return false
}
