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
			if !ok || pod.Spec.HostNetwork || isTerminalPod(pod) {
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

// isTerminalPod reports whether a pod has reached a terminal phase.
// Terminal pods may retain stale IPs in status after the addresses are reused.
func isTerminalPod(pod *v1.Pod) bool {
	return pod.Status.Phase == v1.PodSucceeded || pod.Status.Phase == v1.PodFailed
}

// LookupPod implements the Resolver interface using the informer's index.
func (r *InformerResolver) LookupPod(ip string) (string, bool) {
	objs, err := r.podIndexer.ByIndex(PodIPIndex, ip)
	if err != nil || len(objs) == 0 {
		return "", false
	}
	// If multiple pods share the same IP, prefer a pod that is not being
	// deleted, then a running pod. A pod being deleted still shows Running
	// with its IPs after its sandbox is gone, and by then the IP may belong
	// to another pod.
	var found *v1.Pod
	for _, obj := range objs {
		if pod, ok := obj.(*v1.Pod); ok && (found == nil || podPriority(pod) > podPriority(found)) {
			found = pod
		}
	}
	if found == nil {
		return "", false
	}
	key, err := cache.MetaNamespaceKeyFunc(found)
	if err != nil {
		return "", false
	}
	return key, true
}

// podPriority ranks the pods that share an IP, not being deleted ranks above
// running.
func podPriority(pod *v1.Pod) int {
	priority := 0
	if pod.DeletionTimestamp == nil {
		priority += 2
	}
	if pod.Status.Phase == v1.PodRunning {
		priority++
	}
	return priority
}
