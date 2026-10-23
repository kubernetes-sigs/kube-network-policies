package podinfo

import (
	v1 "k8s.io/api/core/v1"
	coreinformers "k8s.io/client-go/informers/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	"sigs.k8s.io/kube-network-policies/pkg/api"
)

// PodUIDIndex is the name of the indexer that maps the pod UID to the pod
// object. Pod names are reused, the UID is not.
const PodUIDIndex = "podUIDIndex"

// InformerProvider is an implementation of Provider that uses
// Kubernetes informers and an optional NRI plugin to find pod information.
type InformerProvider struct {
	podIndexer cache.Indexer
	nsLister   corelisters.NamespaceLister
	nodeLister corelisters.NodeLister
	local      LocalResolver
	resolvers  []IPResolver
}

// NewInformerProvider creates a new pod info provider.
// The local resolver, the NRI one, can be nil if the runtime does not
// provide it. The nodeLister can be nil if node information is not required.
func NewInformerProvider(
	podInformer coreinformers.PodInformer,
	nsInfomer coreinformers.NamespaceInformer,
	nodeInformer coreinformers.NodeInformer,
	local LocalResolver,
	resolvers []IPResolver,
) (*InformerProvider, error) {
	err := podInformer.Informer().AddIndexers(cache.Indexers{
		PodUIDIndex: func(obj interface{}) ([]string, error) {
			pod, ok := obj.(*v1.Pod)
			if !ok {
				return []string{}, nil
			}
			return []string{api.PodUID(pod)}, nil
		},
	})
	if err != nil {
		return nil, err
	}

	provider := &InformerProvider{
		podIndexer: podInformer.Informer().GetIndexer(),
		nsLister:   nsInfomer.Lister(),
		local:      local,
		resolvers:  resolvers,
	}

	// nodeInformer is optional only used for AdminNetworkPolicies
	if nodeInformer != nil {
		provider.nodeLister = nodeInformer.Lister()
	}

	return provider, nil
}

// GetPodInfoByIP implements the Provider interface.
//
// The local resolver decides which local pod owns the IP, the other resolvers
// only answer for the IPs it does not know, the pods of other nodes. The pod
// details come from the informer when it has that pod, it is the only source
// of the container ports and node labels. When the informer is behind, the
// details come from the local resolver.
func (p *InformerProvider) GetPodInfoByIP(podIP string) (*api.PodInfo, bool) {
	if p.local != nil {
		if uid, ok := p.local.LookupPod(podIP); ok {
			if pod, ok := p.getPod(uid); ok {
				return p.podInfo(pod), true
			}
			klog.V(4).Infof("Pod with UID %s for IP %s is not in the informer, using the local resolver information", uid, podIP)
			return p.local.GetPodInfoByIP(podIP)
		}
	}

	for _, resolver := range p.resolvers {
		uid, ok := resolver.LookupPod(podIP)
		if !ok {
			continue
		}
		if pod, ok := p.getPod(uid); ok {
			return p.podInfo(pod), true
		}
	}

	if p.local == nil && len(p.resolvers) == 0 {
		if pod, ok := p.searchPodByIP(podIP); ok {
			return p.podInfo(pod), true
		}
	}
	return nil, false
}

// getPod returns the informer pod with the UID if it still owns its IPs.
func (p *InformerProvider) getPod(uid string) (*v1.Pod, bool) {
	objs, err := p.podIndexer.ByIndex(PodUIDIndex, uid)
	if err != nil || len(objs) != 1 {
		return nil, false
	}
	pod, ok := objs[0].(*v1.Pod)
	if !ok {
		return nil, false
	}
	// The local resolver may still point to a terminal pod while the runtime
	// tears down its sandbox. The pod details come from the local resolver
	// then.
	if !api.PodOwnsIPs(pod) {
		klog.V(4).Infof("Skipping pod %s/%s in phase %s", pod.Namespace, pod.Name, pod.Status.Phase)
		return nil, false
	}
	return pod, true
}

// searchPodByIP finds a pod by IP with a linear search over the informer,
// used only when there are no resolvers.
func (p *InformerProvider) searchPodByIP(podIP string) (*v1.Pod, bool) {
	for _, obj := range p.podIndexer.List() {
		pod, ok := obj.(*v1.Pod)
		if !ok || !api.PodOwnsIPs(pod) {
			continue
		}

		for _, ip := range pod.Status.PodIPs {
			if ip.IP == podIP {
				return pod, true
			}
		}
	}
	return nil, false
}

// podInfo builds the PodInfo of an informer pod.
func (p *InformerProvider) podInfo(pod *v1.Pod) *api.PodInfo {
	var nsLabels, nodeLabels map[string]string

	if p.nsLister != nil {
		ns, err := p.nsLister.Get(pod.Namespace)
		if err == nil {
			nsLabels = ns.Labels
		}
	}

	if p.nodeLister != nil {
		node, err := p.nodeLister.Get(pod.Spec.NodeName)
		if err == nil {
			nodeLabels = node.Labels
		}
	}

	return api.NewPodInfo(pod, nsLabels, nodeLabels, "")
}
