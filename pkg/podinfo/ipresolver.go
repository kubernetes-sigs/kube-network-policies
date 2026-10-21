package podinfo

import (
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/kube-network-policies/pkg/api"
)

// PodIdentity identifies the pod that has an IP.
type PodIdentity struct {
	Namespace string
	Name      string
	// UID is empty if the resolver does not know it.
	UID types.UID
	// SandboxID is the sandbox that has the IP, empty if the resolver does not
	// know the sandboxes.
	SandboxID string
	// PodInfo is what the resolver knows about the pod, it is used when the
	// informer does not have the pod with this UID. It is nil if the resolver
	// only knows the identity.
	PodInfo *api.PodInfo
}

// IPResolver defines an interface for resolving an IP address to a pod.
type IPResolver interface {
	// LookupPod abstracts the logic of finding a pod given its IP.
	// It returns the pod identity and true if found, otherwise false.
	LookupPod(ip string) (PodIdentity, bool)
}

// FinishedPodReleaser is implemented by resolvers that can keep the IPs of a
// pod after it finished. ReleaseFinishedPod is called with the identity that
// the resolver found for the IP when the informer shows that the pod with that
// UID has finished.
type FinishedPodReleaser interface {
	ReleaseFinishedPod(ip string, identity PodIdentity)
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
func (r *InformerResolver) LookupPod(ip string) (PodIdentity, bool) {
	objs, err := r.podIndexer.ByIndex(PodIPIndex, ip)
	if err != nil || len(objs) == 0 {
		return PodIdentity{}, false
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
		return PodIdentity{}, false
	}
	return PodIdentity{Namespace: found.Namespace, Name: found.Name, UID: found.UID}, true
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
