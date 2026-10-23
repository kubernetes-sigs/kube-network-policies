package podinfo

import (
	"cmp"
	"slices"

	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/kube-network-policies/pkg/api"
)

// IPResolver defines an interface for resolving an IP address to a pod's key ("namespace/name").
type IPResolver interface {
	// LookupPod abstracts the logic of finding a pod's key given its IP.
	// It returns the key and true if found, otherwise an empty string and false.
	LookupPod(ip string) (string, bool)
}

// --- Informer-based Resolver ---

const (
	// PodIPIndex is the name of the indexer that maps pod IPs to pod objects.
	PodIPIndex = "podIPKeyIndex"
)

// InformerResolver is an implementation of Resolver that uses a pod informer index.
type InformerResolver struct {
	podIndexer cache.Indexer
}

// NewInformerResolver creates a new resolver that looks up pods in a Kubernetes informer.
func NewInformerResolver(podInformer cache.SharedIndexInformer) (*InformerResolver, error) {
	// Add the IP indexer to the pod informer.
	err := podInformer.AddIndexers(cache.Indexers{
		PodIPIndex: func(obj interface{}) ([]string, error) {
			pod, ok := obj.(*v1.Pod)
			if !ok || !api.PodOwnsIPs(pod) {
				return []string{}, nil
			}
			ips := make([]string, 0, len(pod.Status.PodIPs))
			for _, ip := range pod.Status.PodIPs {
				ips = append(ips, ip.IP)
			}
			return ips, nil
		},
	})
	if err != nil {
		return nil, err
	}

	return &InformerResolver{
		podIndexer: podInformer.GetIndexer(),
	}, nil
}

// LookupPod implements the Resolver interface using the informer's index.
func (r *InformerResolver) LookupPod(ip string) (string, bool) {
	objs, err := r.podIndexer.ByIndex(PodIPIndex, ip)
	if err != nil || len(objs) == 0 {
		return "", false
	}
	pods := make([]*v1.Pod, 0, len(objs))
	for _, obj := range objs {
		if pod, ok := obj.(*v1.Pod); ok {
			pods = append(pods, pod)
		}
	}
	if len(pods) == 0 {
		return "", false
	}
	// If multiple pods share the IP prefer the one that is not being deleted,
	// then the Running one. A pod being deleted still reports Running with its
	// IPs after its sandbox is gone, and by then another pod may own the IP.
	best := slices.MaxFunc(pods, func(a, b *v1.Pod) int {
		return cmp.Compare(ownershipRank(a), ownershipRank(b))
	})
	key, err := cache.MetaNamespaceKeyFunc(best)
	if err != nil {
		return "", false
	}
	return key, true
}

// ownershipRank scores how likely a pod is to own the IPs in its status.
func ownershipRank(pod *v1.Pod) int {
	rank := 0
	if pod.DeletionTimestamp == nil {
		rank += 2
	}
	if pod.Status.Phase == v1.PodRunning {
		rank++
	}
	return rank
}
