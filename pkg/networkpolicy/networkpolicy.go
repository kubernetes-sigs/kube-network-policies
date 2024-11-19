package networkpolicy

import (
	"context"
	"net"

	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/klog/v2"
)

// getPodsForNetworkPolicyNode obtains all the Pods selected by the network policy for current Node
func (c *Controller) getLocalPodsForNetworkPolicy(networkPolicy *networkingv1.NetworkPolicy) []*v1.Pod {
	if networkPolicy == nil {
		return nil
	}
	podSelector, err := metav1.LabelSelectorAsSelector(&networkPolicy.Spec.PodSelector)
	if err != nil {
		klog.InfoS("parsing PodSelector", "error", err)
		return nil
	}
	pods, err := c.podLister.Pods(networkPolicy.Namespace).List(podSelector)
	if err != nil {
		return nil
	}
	result := []*v1.Pod{}
	for _, pod := range pods {
		if pod.Spec.NodeName == c.config.NodeName {
			result = append(result, pod)
		}
	}
	return result
}

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
			klog.InfoS("parsing PodSelector", "error", err)
			continue
		}
		// networkPolicy does not select the pod try the next network policy
		if podSelector.Matches(labels.Set(pod.Labels)) {
			result = append(result, policy)
		}
	}
	return result
}

// validator obtains a verdict for network policies that applies to a src Pod in the direction
// passed as parameter
func (c *Controller) evaluator(
	ctx context.Context, networkPolicies []*networkingv1.NetworkPolicy, networkPolictType networkingv1.PolicyType,
	srcPod *v1.Pod, srcPort int, dstPod *v1.Pod, dstIP net.IP, dstPort int, proto v1.Protocol) bool {

	tlogger := klog.FromContext(ctx).V(2)

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
					if tlogger.Enabled() {
						tlogger.Info("Pod has limited all egress traffic", "pod", klog.KObj(srcPod), "policy", netpol)
					}
					continue
				}
				// This evaluator only evaluates one policyType, if it matches then traffic is allowed
				if c.evaluateEgress(ctx, netpol.Namespace, netpol.Spec.Egress, srcPod, dstPod, dstIP, dstPort, proto) {
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
					if tlogger.Enabled() {
						tlogger.Info("Pod has limited all ingress traffic", "pod", klog.KObj(dstPod), "policy", klog.KObj(netpol))
					}
					continue
				}
				// This evaluator only evaluates one policyType, if it matches then traffic is allowed
				if c.evaluateIngress(ctx, netpol.Namespace, netpol.Spec.Ingress, srcPod, srcPort, dstPod, dstIP, proto) {
					return true
				}
			}
		}
	}

	return verdict
}

func (c *Controller) evaluateIngress(ctx context.Context, netpolNamespace string, ingressRules []networkingv1.NetworkPolicyIngressRule, srcPod *v1.Pod, srcPort int, dstPod *v1.Pod, dstIP net.IP, proto v1.Protocol) bool {
	tlogger := klog.FromContext(ctx).V(2)
	if tlogger.Enabled() {
		tlogger = tlogger.WithValues("pod", klog.KObj(srcPod))
	}
	// assume srcPod and ingressRules are not nil
	if len(ingressRules) == 0 {
		if tlogger.Enabled() {
			tlogger.Info("Pod has allowed all ingress traffic")
		}
		return true
	}

	for _, rule := range ingressRules {
		// Evaluate if Port is accessible in the specified Pod
		if !c.evaluatePorts(rule.Ports, srcPod, srcPort, proto) {
			if tlogger.Enabled() {
				tlogger.Info("Pod is not allowed to be connected on port", "src-port", srcPort)
			}
			continue
		}

		// from is a list of sources which should be able to access the pods selected for this rule.
		// Items in this list are combined using a logical OR operation. If this field is
		// empty or missing, this rule matches all sources (traffic not restricted by
		// source). If this field is present and contains at least one item, this rule
		// allows traffic only if the traffic matches at least one item in the from list.
		if len(rule.From) == 0 {
			if tlogger.Enabled() {
				tlogger.Info("Pod is allowed to connect from any destination")
			}
			return true
		}
		for _, peer := range rule.From {
			// IPBlock describes a particular CIDR (Ex. "192.168.1.0/24","2001:db8::/64") that is allowed
			// to the pods matched by a NetworkPolicySpec's podSelector. The except entry describes CIDRs
			// that should not be included within this rule.
			if peer.IPBlock != nil {
				if c.evaluateIPBlocks(peer.IPBlock, dstIP) {
					if tlogger.Enabled() {
						tlogger.Info("Pod is not accessible from dest", "dest", dstIP)
					}
					return true
				}
				continue
			}

			// traffic coming from external does not match selectors
			if dstPod == nil {
				continue
			}

			if peer.NamespaceSelector != nil || peer.PodSelector != nil {
				if c.evaluateSelectors(ctx, peer.PodSelector, peer.NamespaceSelector, dstPod, netpolNamespace) {
					if tlogger.Enabled() {
						tlogger.Info("Pod is accessible from Pod because match selectors", "dstPod", klog.KObj(dstPod))
					}
					return true
				}
			}
		}
	}
	return false
}

func (c *Controller) evaluateEgress(ctx context.Context, netpolNamespace string, egressRules []networkingv1.NetworkPolicyEgressRule, srcPod *v1.Pod, dstPod *v1.Pod, dstIP net.IP, dstPort int, proto v1.Protocol) bool {
	tlogger := klog.FromContext(ctx).V(2)
	if tlogger.Enabled() {
		tlogger = tlogger.WithValues("pod", klog.KObj(srcPod))
	}
	if len(egressRules) == 0 {
		tlogger.Info("Pod has allowed all egress traffic")
		return true
	}

	for _, rule := range egressRules {
		// Evaluate if Pod is allowed to connect to dstPort
		if !c.evaluatePorts(rule.Ports, dstPod, dstPort, proto) {
			if tlogger.Enabled() {
				tlogger.Info("Pod is not allowed to connect to port", "port", dstPort)
			}
			continue
		}
		// to is a list of destinations for outgoing traffic of pods selected for this rule.
		// Items in this list are combined using a logical OR operation. If this field is
		// empty or missing, this rule matches all destinations (traffic not restricted by
		// destination). If this field is present and contains at least one item, this rule
		// allows traffic only if the traffic matches at least one item in the to list.
		if len(rule.To) == 0 {
			if tlogger.Enabled() {
				tlogger.Info("Pod is allowed to connect to any destination")
			}
			return true
		}
		for _, peer := range rule.To {
			// IPBlock describes a particular CIDR (Ex. "192.168.1.0/24","2001:db8::/64") that is allowed
			// to the pods matched by a NetworkPolicySpec's podSelector. The except entry describes CIDRs
			// that should not be included within this rule.
			if peer.IPBlock != nil {
				if c.evaluateIPBlocks(peer.IPBlock, dstIP) {
					if tlogger.Enabled() {
						tlogger.Info("Pod is allowed to connect to dst", "dst", dstIP)
					}
					return true
				}
				continue
			}

			// NamespaceSelector and PodSelector only apply to destination Pods
			if dstPod == nil {
				continue
			}

			if peer.NamespaceSelector != nil || peer.PodSelector != nil {
				if c.evaluateSelectors(ctx, peer.PodSelector, peer.NamespaceSelector, dstPod, netpolNamespace) {
					if tlogger.Enabled() {
						tlogger.Info("Pod is allowed to connect because of Pod and Namespace selectors")
					}
					return true
				}
			}
		}
	}
	return false
}

func (c *Controller) evaluateSelectors(ctx context.Context, peerPodSelector *metav1.LabelSelector, peerNSSelector *metav1.LabelSelector, pod *v1.Pod, policyNs string) bool {
	// avoid panics
	if pod == nil {
		return true
	}
	logger := klog.FromContext(ctx)

	// podSelector is a label selector which selects pods. This field follows standard label
	// selector semantics; if present but empty, it selects all pods.
	// If namespaceSelector is also set, then the NetworkPolicyPeer as a whole selects
	// the pods matching podSelector in the Namespaces selected by NamespaceSelector.
	if peerPodSelector != nil {
		podSelector, err := metav1.LabelSelectorAsSelector(peerPodSelector)
		if err != nil {
			logger.Error(err, "Accepting packet")
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
			logger.Error(err, "Accepting packet")
			return true
		}

		namespaces, err := c.namespaceLister.List(nsSelector)
		if err != nil {
			logger.Error(err, "Accepting packet")
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
