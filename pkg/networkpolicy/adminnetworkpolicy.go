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
	npav1alpha1 "sigs.k8s.io/network-policy-api/apis/v1alpha1"
	anpinformers "sigs.k8s.io/network-policy-api/pkg/client/informers/externalversions/apis/v1alpha1"
	anplisters "sigs.k8s.io/network-policy-api/pkg/client/listers/apis/v1alpha1"
)

// AdminNetworkPolicy implements the PolicyEvaluator interface for the ANP API.
type AdminNetworkPolicy struct {
	anpLister      anplisters.AdminNetworkPolicyLister
	anpSynced      cache.InformerSynced
	domainResolver api.DomainResolver
}

var _ api.PolicyEvaluator = &AdminNetworkPolicy{}

// NewAdminNetworkPolicy creates a new ANP implementation.
func NewAdminNetworkPolicy(anpInformer anpinformers.AdminNetworkPolicyInformer, domainResolver api.DomainResolver) *AdminNetworkPolicy {
	return &AdminNetworkPolicy{
		anpLister:      anpInformer.Lister(),
		anpSynced:      anpInformer.Informer().HasSynced,
		domainResolver: domainResolver,
	}
}

func (a *AdminNetworkPolicy) Name() string {
	return "AdminNetworkPolicy"
}

func (a *AdminNetworkPolicy) Ready() bool {
	return a.anpSynced()
}

func (a *AdminNetworkPolicy) SetDataplaneSyncCallback(syncFn api.SyncFunc) {
	// No-op for AdminNetworkPolicy as it doesn't directly control dataplane rules.
	// The controller will handle syncing based on policy changes.
}

func (a *AdminNetworkPolicy) ManagedIPs(ctx context.Context) ([]netip.Addr, bool, error) {
	// divert all traffic to user space to evaluate all traffic to ensure that the correct
	// AdminNetworkPolicies are applied.
	return nil, true, nil
}

func (a *AdminNetworkPolicy) EvaluateIngress(ctx context.Context, p *network.Packet, srcPod, dstPod *api.PodInfo) (api.Verdict, error) {
	logger := klog.FromContext(ctx)

	allPolicies, err := a.anpLister.List(labels.Everything())
	if err != nil || len(allPolicies) == 0 {
		return api.VerdictNext, err
	}

	dstPodAdminNetworkPolicies := getAdminNetworkPoliciesForPod(dstPod, allPolicies)
	if len(dstPodAdminNetworkPolicies) == 0 {
		logger.V(2).Info("Ingress AdminNetworkPolicies does not apply")
		return api.VerdictNext, nil
	}
	ingressAction := a.evaluateAdminIngress(dstPodAdminNetworkPolicies, srcPod, dstPod, p.DstPort, p.Proto)
	logger.V(2).Info("Ingress AdminNetworkPolicies", "npolicies", len(dstPodAdminNetworkPolicies), "action", ingressAction)

	switch ingressAction {
	case npav1alpha1.AdminNetworkPolicyRuleActionAllow:
		return api.VerdictAccept, nil
	case npav1alpha1.AdminNetworkPolicyRuleActionDeny:
		return api.VerdictDeny, nil
	case npav1alpha1.AdminNetworkPolicyRuleActionPass:
		return api.VerdictNext, nil
	default: // Pass
		return api.VerdictNext, nil
	}
}

func (a *AdminNetworkPolicy) EvaluateEgress(ctx context.Context, p *network.Packet, srcPod, dstPod *api.PodInfo) (api.Verdict, error) {
	logger := klog.FromContext(ctx)

	allPolicies, err := a.anpLister.List(labels.Everything())
	if err != nil || len(allPolicies) == 0 {
		return api.VerdictNext, err
	}

	srcPodAdminNetworkPolicies := getAdminNetworkPoliciesForPod(srcPod, allPolicies)
	if len(srcPodAdminNetworkPolicies) == 0 {
		logger.V(2).Info("Egress AdminNetworkPolicies does not apply")
		return api.VerdictNext, nil
	}
	egressAction := a.evaluateAdminEgress(srcPodAdminNetworkPolicies, dstPod, p.DstIP, p.DstPort, p.Proto)
	logger.V(2).Info("Egress AdminNetworkPolicies", "npolicies", len(srcPodAdminNetworkPolicies), "action", egressAction)

	switch egressAction {
	case npav1alpha1.AdminNetworkPolicyRuleActionAllow:
		return api.VerdictAccept, nil
	case npav1alpha1.AdminNetworkPolicyRuleActionDeny:
		return api.VerdictDeny, nil
	case npav1alpha1.AdminNetworkPolicyRuleActionPass:
		return api.VerdictNext, nil
	default: // Pass
		return api.VerdictNext, nil
	}
}

// getAdminNetworkPoliciesForPod filters a list of all ANPs and returns only those
// that apply to a given pod, sorted by priority.
// A policy applies to a pod if the pod matches the policy's 'Subject' field.
// Policies are sorted first by their 'Priority' field (lower value is higher precedence)
// and then by name for stable ordering.
func getAdminNetworkPoliciesForPod(pod *api.PodInfo, allPolicies []*npav1alpha1.AdminNetworkPolicy) []*npav1alpha1.AdminNetworkPolicy {
	if pod == nil {
		return nil
	}

	var result []*npav1alpha1.AdminNetworkPolicy
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

	// Per ANP API spec, rules with lower priority values have higher precedence.
	slices.SortFunc(result, func(a, b *npav1alpha1.AdminNetworkPolicy) int {
		if n := cmp.Compare(a.Spec.Priority, b.Spec.Priority); n != 0 {
			return n
		}
		// If priorities are equal, sort by name to ensure deterministic evaluation order.
		return cmp.Compare(a.Name, b.Name)
	})
	return result
}

// evaluateAdminEgress evaluates a list of egress policies for a traffic flow.
// It iterates through the sorted policies and their rules, returning the action
// of the first matching rule.
// An egress rule matches if its 'To' peer selector matches the traffic's destination
// and its 'Ports' selector matches the destination port/protocol.
// If no rule matches, it returns 'Pass'.
func (a *AdminNetworkPolicy) evaluateAdminEgress(
	policies []*npav1alpha1.AdminNetworkPolicy,
	dstPod *api.PodInfo,
	dstIP net.IP,
	dstPort int,
	protocol v1.Protocol,
) npav1alpha1.AdminNetworkPolicyRuleAction {
	for _, policy := range policies {
		for _, rule := range policy.Spec.Egress {
			// If rule.Ports is specified, it must match the destination port.
			if rule.Ports != nil {
				// For egress, a NamedPort must be resolved on the destination pod.
				if !evaluateAdminNetworkPolicyPort(*rule.Ports, dstPod, dstPort, protocol) {
					continue
				}
			}
			// The 'To' field lists destinations. The rule applies if any peer matches.
			for _, to := range rule.To {
				if to.Namespaces != nil && dstPod != nil && matchesSelector(to.Namespaces, dstPod.Namespace.Labels) {
					return rule.Action
				}

				if to.Pods != nil && dstPod != nil &&
					matchesSelector(&to.Pods.NamespaceSelector, dstPod.Namespace.Labels) &&
					matchesSelector(&to.Pods.PodSelector, dstPod.Labels) {
					return rule.Action
				}

				if to.Nodes != nil && dstPod != nil && matchesSelector(to.Nodes, dstPod.Node.Labels) {
					return rule.Action
				}

				// Check for CIDR match for traffic to non-pod or external destinations.
				for _, network := range to.Networks {
					_, cidr, err := net.ParseCIDR(string(network))
					if err != nil { // Should be validated by the API.
						continue
					}
					if cidr.Contains(dstIP) {
						return rule.Action
					}
				}
				for _, domain := range to.DomainNames {
					if a.domainResolver.ContainsIP(string(domain), dstIP) {
						return rule.Action
					}
				}
			}
		}
	}
	// Per ANP spec, if no rule matches, the default action is 'Pass'.
	return npav1alpha1.AdminNetworkPolicyRuleActionPass
}

// evaluateAdminIngress evaluates a list of ingress policies for a traffic flow.
// It iterates through the sorted policies and their rules, returning the action
// of the first matching rule.
// An ingress rule matches if its 'From' peer selector matches the traffic's source
// and its 'Ports' selector matches the destination port/protocol on the subject pod.
// If no rule matches, it returns 'Pass'.
func (a *AdminNetworkPolicy) evaluateAdminIngress(
	policies []*npav1alpha1.AdminNetworkPolicy,
	srcPod, dstPod *api.PodInfo, // srcPod for peer matching, dstPod for port resolution
	dstPort int,
	protocol v1.Protocol,
) npav1alpha1.AdminNetworkPolicyRuleAction {
	// Ingress rules only apply if the source is a pod within the cluster.
	if srcPod == nil {
		return npav1alpha1.AdminNetworkPolicyRuleActionPass
	}
	for _, policy := range policies {
		for _, rule := range policy.Spec.Ingress {
			// If rule.Ports is specified, it must match the destination port.
			if rule.Ports != nil {
				// For ingress, a NamedPort is resolved on the pod the policy applies to (the destination pod).
				if !evaluateAdminNetworkPolicyPort(*rule.Ports, dstPod, dstPort, protocol) {
					continue
				}
			}
			for _, from := range rule.From {
				if from.Namespaces != nil && matchesSelector(from.Namespaces, srcPod.Namespace.Labels) {
					return rule.Action
				}

				if from.Pods != nil &&
					matchesSelector(&from.Pods.NamespaceSelector, srcPod.Namespace.Labels) &&
					matchesSelector(&from.Pods.PodSelector, srcPod.Labels) {
					return rule.Action
				}
			}
		}
	}
	// Per ANP spec, if no rule matches, the default action is 'Pass'.
	return npav1alpha1.AdminNetworkPolicyRuleActionPass
}

// evaluateAdminNetworkPolicyPort checks if a specific port and protocol match any
// of the port selectors in the given list.
// A 'pod' parameter is required for resolving NamedPorts.
func evaluateAdminNetworkPolicyPort(
	policyPorts []npav1alpha1.AdminNetworkPolicyPort,
	pod *api.PodInfo, // The pod on which a NamedPort should be resolved.
	port int,
	protocol v1.Protocol,
) bool {
	// If the port list is empty, the rule matches all ports.
	if len(policyPorts) == 0 {
		return true
	}

	for _, policyPort := range policyPorts {
		// Match by port number and protocol.
		// Port number
		if policyPort.PortNumber != nil &&
			policyPort.PortNumber.Port == int32(port) &&
			policyPort.PortNumber.Protocol == protocol {
			return true
		}

		// Match by named port. This requires pod info to look up the container port name.
		if policyPort.NamedPort != nil {
			if pod == nil {
				continue
			}
			for _, containerPort := range pod.ContainerPorts {
				if containerPort.Name == *policyPort.NamedPort {
					return true
				}
			}
		}

		// Match by a range of ports and protocol.
		if policyPort.PortRange != nil &&
			policyPort.PortRange.Protocol == protocol &&
			policyPort.PortRange.Start <= int32(port) &&
			policyPort.PortRange.End >= int32(port) {
			return true
		}
	}

	// No selector matched the given port and protocol.
	return false
}
