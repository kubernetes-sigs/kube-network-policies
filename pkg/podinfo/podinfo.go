package podinfo

import (
	v1 "k8s.io/api/core/v1"
	coreinformers "k8s.io/client-go/informers/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/kube-network-policies/pkg/api"
)

// InformerProvider is an implementation of Provider that uses
// Kubernetes informers and an optional NRI plugin to find pod information.
type InformerProvider struct {
	podIndexer cache.Indexer
	nsLister   corelisters.NamespaceLister
	nodeLister corelisters.NodeLister
	resolvers  []IPResolver
}

// NewInformerProvider creates a new pod info provider.
// The nodeLister can be nil if node information is not required.
func New(
	podInformer coreinformers.PodInformer,
	nsInfomer coreinformers.NamespaceInformer,
	nodeInformer coreinformers.NodeInformer,
	resolvers []IPResolver,
) *InformerProvider {
	provider := &InformerProvider{
		podIndexer: podInformer.Informer().GetIndexer(),
		nsLister:   nsInfomer.Lister(),
		resolvers:  resolvers,
	}

	// nodeInformer is optional only used for AdminNetworkPolicies
	if nodeInformer != nil {
		provider.nodeLister = nodeInformer.Lister()
	}

	return provider
}

// getPodByIP finds a running pod by its IP address using the informer index
// and falling back to the NRI plugin if available.
func (p *InformerProvider) getPodByIP(podIP string) (*v1.Pod, bool) {
	for _, resolver := range p.resolvers {
		if podKey, ok := resolver.LookupPod(podIP); ok {
			obj, exists, err := p.podIndexer.GetByKey(podKey)
			if err == nil && exists {
				return obj.(*v1.Pod), true
			}
		}
	}
	if len(p.resolvers) > 0 {
		return nil, false
	}

	// if not resolver is provided use a linear search
	for _, obj := range p.podIndexer.List() {
		pod, ok := obj.(*v1.Pod)
		if !ok || pod.Spec.HostNetwork || len(pod.Status.PodIP) == 0 {
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

// GetPodInfoByIP implements the Provider interface.
func (p *InformerProvider) GetPodInfoByIP(podIP string) (*api.PodInfo, bool) {
	pod, ok := p.getPodByIP(podIP)
	if !ok {
		return nil, false
	}

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

	return api.NewPodInfo(pod, nsLabels, nodeLabels, ""), true
}
