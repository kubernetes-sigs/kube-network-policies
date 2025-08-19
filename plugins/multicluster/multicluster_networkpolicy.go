package multicluster

import (
	"context"
	"net"
	"net/netip"

	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	networkinginformers "k8s.io/client-go/informers/networking/v1"
	networkinglisters "k8s.io/client-go/listers/networking/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	"sigs.k8s.io/kube-network-policies/pkg/api"
	"sigs.k8s.io/kube-network-policies/pkg/network"
	"sigs.k8s.io/kube-network-policies/pkg/networkpolicy"
)

const (
	ClusterNameLabel  = "networking.x-k8s.io/cluster-name"
	ScopeAnnotation   = "networking.x-k8s.io/scope"
	ScopeClusterLocal = "cluster-local"
	ScopeCrossCluster = "cross-cluster"
)

// MultiClusterNetworkPolicy implements the PolicyEvaluator interface for standard Kubernetes NetworkPolicies using iptracker.
type MultiClusterNetworkPolicy struct {
	networkpolicyLister   networkinglisters.NetworkPolicyLister
	networkpoliciesSynced cache.InformerSynced
	syncCallback          api.SyncFunc
	localClusterID        string
}

var _ api.PolicyEvaluator = &MultiClusterNetworkPolicy{}

func NewMultiClusterNetworkPolicy(
	networkpolicyInformer networkinginformers.NetworkPolicyInformer,
	localClusterID string,
) *MultiClusterNetworkPolicy {
	s := &MultiClusterNetworkPolicy{
		networkpolicyLister:   networkpolicyInformer.Lister(),
		networkpoliciesSynced: networkpolicyInformer.Informer().HasSynced,
		syncCallback:          func() {},
		localClusterID:        localClusterID,
	}
	_, _ = networkpolicyInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { s.syncCallback() },
		UpdateFunc: func(old, cur interface{}) { s.syncCallback() },
		DeleteFunc: func(obj interface{}) { s.syncCallback() },
	})
	return s
}

func (s *MultiClusterNetworkPolicy) Name() string {
	return "MultiClusterNetworkPolicy"
}

func (s *MultiClusterNetworkPolicy) SetDataplaneSyncCallback(syncFn api.SyncFunc) {
	if syncFn != nil {
		s.syncCallback = syncFn
	}
}

func (s *MultiClusterNetworkPolicy) Ready() bool { return s.networkpoliciesSynced() }

func (s *MultiClusterNetworkPolicy) ManagedIPs(ctx context.Context) ([]netip.Addr, bool, error) {
	return nil, true, nil
}

func (s *MultiClusterNetworkPolicy) EvaluateIngress(ctx context.Context, p *network.Packet, srcPod, dstPod *api.PodInfo) (api.Verdict, error) {
	policies := s.getNetworkPoliciesForPod(dstPod)
	if len(policies) == 0 {
		return api.VerdictNext, nil
	}
	if !s.evaluatePolicyDirection(ctx, policies, networkingv1.PolicyTypeIngress, dstPod, p.DstPort, srcPod, p.SrcIP, p.SrcPort, p.Proto) {
		return api.VerdictDeny, nil
	}
	return api.VerdictAccept, nil
}

func (s *MultiClusterNetworkPolicy) EvaluateEgress(ctx context.Context, p *network.Packet, srcPod, dstPod *api.PodInfo) (api.Verdict, error) {
	policies := s.getNetworkPoliciesForPod(srcPod)
	if len(policies) == 0 {
		return api.VerdictNext, nil
	}
	if !s.evaluatePolicyDirection(ctx, policies, networkingv1.PolicyTypeEgress, srcPod, p.SrcPort, dstPod, p.DstIP, p.DstPort, p.Proto) {
		return api.VerdictDeny, nil
	}
	return api.VerdictAccept, nil
}

// evaluatePolicyDirection is the plugin-specific wrapper that handles the policy evaluation.
func (s *MultiClusterNetworkPolicy) evaluatePolicyDirection(
	ctx context.Context, networkPolicies []*networkingv1.NetworkPolicy, networkPolicyType networkingv1.PolicyType,
	subjectPod *api.PodInfo, subjectPort int, peerPod *api.PodInfo, peerIP net.IP, peerPort int, proto v1.Protocol) bool {

	verdict := true // Default to allow if no policies of the given type apply

	for _, netpol := range networkPolicies {
		policyApplies := false
		for _, policyType := range netpol.Spec.PolicyTypes {
			if policyType == networkPolicyType {
				policyApplies = true
				break
			}
		}
		if !policyApplies {
			continue
		}

		verdict = false // If any policy of this type applies, the default becomes deny.

		if networkPolicyType == networkingv1.PolicyTypeEgress {
			if netpol.Spec.Egress == nil {
				continue
			}
			if s.evaluateEgressRules(ctx, netpol, subjectPod, peerPod, peerIP, peerPort, proto) {
				return true
			}
		}

		if networkPolicyType == networkingv1.PolicyTypeIngress {
			if netpol.Spec.Ingress == nil {
				continue
			}
			if s.evaluateIngressRules(ctx, netpol, peerPod, peerPort, subjectPod, peerIP, proto) {
				return true
			}
		}
	}
	return verdict
}

// evaluateEgressRules iterates through egress rules and uses the custom peer evaluation.
func (s *MultiClusterNetworkPolicy) evaluateEgressRules(ctx context.Context, policy *networkingv1.NetworkPolicy, srcPod, dstPod *api.PodInfo, dstIP net.IP, dstPort int, proto v1.Protocol) bool {
	for _, rule := range policy.Spec.Egress {
		if !networkpolicy.EvaluatePorts(rule.Ports, dstPod, dstPort, proto) {
			continue
		}
		if len(rule.To) == 0 {
			return true
		}
		for _, peer := range rule.To {
			if s.evaluatePeer(ctx, peer, dstPod, dstIP, policy) {
				return true
			}
		}
	}
	return false
}

// evaluateIngressRules iterates through ingress rules and uses the custom peer evaluation.
func (s *MultiClusterNetworkPolicy) evaluateIngressRules(ctx context.Context, policy *networkingv1.NetworkPolicy, srcPod *api.PodInfo, srcPort int, dstPod *api.PodInfo, srcIP net.IP, proto v1.Protocol) bool {
	for _, rule := range policy.Spec.Ingress {
		if !networkpolicy.EvaluatePorts(rule.Ports, dstPod, srcPort, proto) {
			continue
		}
		if len(rule.From) == 0 {
			return true
		}
		for _, peer := range rule.From {
			if s.evaluatePeer(ctx, peer, srcPod, srcIP, policy) {
				return true
			}
		}
	}
	return false
}

// evaluatePeer simplifies the logic: if the special label is present, it's a cross-cluster rule.
// If not, it's a local-cluster rule.
func (s *MultiClusterNetworkPolicy) evaluatePeer(ctx context.Context, peer networkingv1.NetworkPolicyPeer, peerPod *api.PodInfo, peerIP net.IP, policy *networkingv1.NetworkPolicy) bool {
	// Handle IPBlock separately as it's not cluster-aware.
	if peer.IPBlock != nil {
		return networkpolicy.EvaluateIPBlocks(peer.IPBlock, peerIP)
	}

	// All other peer types require a pod.
	if peerPod == nil {
		return false
	}

	scope := policy.Annotations[ScopeAnnotation]

	if scope == ScopeCrossCluster {
		podSelector := peer.PodSelector
		namespaceSelector := peer.NamespaceSelector

		nsHasLabel, nsClusterAlias := hasClusterLabel(namespaceSelector)
		psHasLabel, psClusterAlias := hasClusterLabel(podSelector)

		if !nsHasLabel && !psHasLabel {
			klog.Warningf("cross-cluster policy %s/%s is missing cross-cluster label, allowing traffic", policy.Namespace, policy.Name)
			return true
		}
		if nsHasLabel && psHasLabel && nsClusterAlias != psClusterAlias {
			klog.Warningf("cross-cluster policy %s/%s has mismatched cluster labels, allowing traffic", policy.Namespace, policy.Name)
			return true
		}

		clusterAlias := nsClusterAlias
		if clusterAlias == "" {
			clusterAlias = psClusterAlias
		}

		if clusterAlias == "" {
			return false
		}
		if peerPod.ClusterId != clusterAlias {
			return false
		}

		if nsHasLabel {
			namespaceSelector = removeClusterLabel(namespaceSelector)
		}
		if psHasLabel {
			podSelector = removeClusterLabel(podSelector)
		}
		return networkpolicy.EvaluateSelectors(ctx, podSelector, namespaceSelector, peerPod, policy.Namespace)
	}

	// For local scope or backward compatibility (no scope annotation), treat the cluster name label as a regular label.
	return networkpolicy.EvaluateSelectors(ctx, peer.PodSelector, peer.NamespaceSelector, nil, policy.Namespace)
}

func hasClusterLabel(selector *metav1.LabelSelector) (bool, string) {
	if selector != nil && selector.MatchLabels != nil {
		if alias, ok := selector.MatchLabels[ClusterNameLabel]; ok {
			return true, alias
		}
	}
	return false, ""
}

func removeClusterLabel(selector *metav1.LabelSelector) *metav1.LabelSelector {
	if selector == nil {
		return nil
	}
	selectorCopy := selector.DeepCopy()
	delete(selectorCopy.MatchLabels, ClusterNameLabel)
	return selectorCopy
}

func (s *MultiClusterNetworkPolicy) getNetworkPoliciesForPod(pod *api.PodInfo) []*networkingv1.NetworkPolicy {
	if pod == nil {
		return nil
	}
	networkPolices, err := s.networkpolicyLister.NetworkPolicies(pod.Namespace.Name).List(labels.Everything())
	if err != nil {
		return nil
	}
	var result []*networkingv1.NetworkPolicy
	for _, policy := range networkPolices {
		podSelector, err := metav1.LabelSelectorAsSelector(&policy.Spec.PodSelector)
		if err != nil {
			continue
		}
		if podSelector.Matches(labels.Set(pod.Labels)) {
			result = append(result, policy)
		}
	}
	return result
}
