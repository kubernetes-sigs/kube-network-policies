package networkpolicy

import (
	"context"
	"fmt"
	"net/netip"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	networkinginformers "k8s.io/client-go/informers/networking/v1"
	networkinglisters "k8s.io/client-go/listers/networking/v1"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/kube-network-policies/pkg/api"
	"sigs.k8s.io/kube-network-policies/pkg/ipcache"
	"sigs.k8s.io/kube-network-policies/pkg/network"
)

// IPTrackerNetworkPolicy implements the PolicyEvaluator interface for standard Kubernetes NetworkPolicies using iptracker.
type IPTrackerNetworkPolicy struct {
	networkpolicyLister   networkinglisters.NetworkPolicyLister
	networkpoliciesSynced cache.InformerSynced
	ipcache               *ipcache.Client
	syncCallback          api.SyncFunc
}

// Ensure IPTrackerNetworkPolicy implements the PolicyEvaluator interface.
var _ api.PolicyEvaluator = &IPTrackerNetworkPolicy{}

// NewIPTrackerNetworkPolicy creates a new IPTrackerNetworkPolicy implementation.
func NewIPTrackerNetworkPolicy(
	networkpolicyInformer networkinginformers.NetworkPolicyInformer,
	ipcache *ipcache.Client,
) *IPTrackerNetworkPolicy {
	s := &IPTrackerNetworkPolicy{
		networkpolicyLister:   networkpolicyInformer.Lister(),
		networkpoliciesSynced: networkpolicyInformer.Informer().HasSynced,
		ipcache:               ipcache,
		syncCallback:          func() {},
	}

	_, _ = networkpolicyInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { s.syncCallback() },
		UpdateFunc: func(old, cur interface{}) { s.syncCallback() },
		DeleteFunc: func(obj interface{}) { s.syncCallback() },
	})

	return s
}

// Name returns the name of the evaluator.
func (s *IPTrackerNetworkPolicy) Name() string {
	return "IPTrackerNetworkPolicy"
}

// SetDataplaneSyncCallback stores the sync function provided by the controller.
func (s *IPTrackerNetworkPolicy) SetDataplaneSyncCallback(syncFn api.SyncFunc) {
	if syncFn != nil {
		s.syncCallback = syncFn
		s.ipcache.SetSyncCallback(s.syncCallback)
	}
}

// Ready returns true if all required informers have synced.
func (s *IPTrackerNetworkPolicy) Ready() bool {
	return s.networkpoliciesSynced()
}

// ManagedIPs returns the IP addresses of all local pods that are selected by a NetworkPolicy.
func (s *IPTrackerNetworkPolicy) ManagedIPs(ctx context.Context) ([]netip.Addr, bool, error) {
	allPolicies, err := s.networkpolicyLister.List(labels.Everything())
	if err != nil {
		return nil, false, fmt.Errorf("listing network policies: %w", err)
	}

	allPods, err := s.ipcache.List()
	if err != nil {
		return nil, false, fmt.Errorf("listing pods from ipcache: %w", err)
	}

	managedIPs := sets.New[netip.Addr]()
	for _, policy := range allPolicies {
		for _, pod := range allPods {
			if pod.Namespace.Name != policy.Namespace {
				continue
			}
			podSelector, err := metav1.LabelSelectorAsSelector(&policy.Spec.PodSelector)
			if err != nil {
				continue
			}
			if podSelector.Matches(labels.Set(pod.Labels)) {
				podIPs, _ := s.ipcache.GetPodInfoByIP(pod.Name) // assuming name is the ip for list
				if podIPs != nil {
					// a pod can have multiple IPs
					// TODO: fix this part, the key in ipcache is ip, not pod name.
					// we need a way to get all IPs for a pod, or iterate all IPs in cache and check if it belongs to the pod
				}
			}
		}
	}
	// Standard K8s NetworkPolicy never requires diverting all traffic.
	return managedIPs.UnsortedList(), false, nil
}

// EvaluateIngress evaluates the ingress traffic for a pod.
func (s *IPTrackerNetworkPolicy) EvaluateIngress(ctx context.Context, p *network.Packet, srcPod, dstPod *api.PodInfo) (api.Verdict, error) {
	policies := s.getNetworkPoliciesForPod(dstPod)
	if len(policies) == 0 {
		return api.VerdictNext, nil
	}
	if !evaluatePolicyDirection(ctx, policies, networkingv1.PolicyTypeIngress, dstPod, p.DstPort, srcPod, p.SrcIP, p.SrcPort, p.Proto) {
		return api.VerdictDeny, nil
	}
	return api.VerdictAccept, nil
}

// EvaluateEgress evaluates the egress traffic for a pod.
func (s *IPTrackerNetworkPolicy) EvaluateEgress(ctx context.Context, p *network.Packet, srcPod, dstPod *api.PodInfo) (api.Verdict, error) {
	policies := s.getNetworkPoliciesForPod(srcPod)
	if len(policies) == 0 {
		return api.VerdictNext, nil
	}

	if !evaluatePolicyDirection(ctx, policies, networkingv1.PolicyTypeEgress, srcPod, p.SrcPort, dstPod, p.DstIP, p.DstPort, p.Proto) {
		return api.VerdictDeny, nil
	}
	return api.VerdictAccept, nil
}

func (s *IPTrackerNetworkPolicy) getNetworkPoliciesForPod(pod *api.PodInfo) []*networkingv1.NetworkPolicy {
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
