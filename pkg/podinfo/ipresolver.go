package podinfo

import (
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
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
			if !ok || pod.Spec.HostNetwork {
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
	// Prefer a running pod if multiple pods share the same IP.
	for _, obj := range objs {
		if pod, ok := obj.(*v1.Pod); ok && pod.Status.Phase == v1.PodRunning {
			key, err := cache.MetaNamespaceKeyFunc(pod)
			if err == nil {
				return key, true
			}
		}
	}
	// Fallback to the first pod found.
	key, err := cache.MetaNamespaceKeyFunc(objs[0])
	if err != nil {
		return "", false
	}
	return key, true
}
