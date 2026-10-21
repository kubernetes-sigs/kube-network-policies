package podinfo

import (
	"fmt"
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
)

// --- Helpers ---

func makePod(namespace, name, ip string, phase v1.PodPhase, hostNetwork bool) *v1.Pod {
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			UID:       types.UID(namespace + "/" + name),
		},
		Spec: v1.PodSpec{
			HostNetwork: hostNetwork,
		},
		Status: v1.PodStatus{
			Phase:  phase,
			PodIP:  ip,
			PodIPs: []v1.PodIP{{IP: ip}},
		},
	}
}

func makePodWithIPs(namespace, name string, ips []string, phase v1.PodPhase) *v1.Pod {
	podIPs := make([]v1.PodIP, len(ips))
	for i, ip := range ips {
		podIPs[i] = v1.PodIP{IP: ip}
	}
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			UID:       types.UID(namespace + "/" + name),
		},
		Status: v1.PodStatus{
			Phase:  phase,
			PodIP:  ips[0],
			PodIPs: podIPs,
		},
	}
}

// lookupKey returns the namespace/name of the pod that the resolver finds with the IP.
func lookupKey(resolver IPResolver, ip string) (string, bool) {
	identity, ok := resolver.LookupPod(ip)
	if !ok {
		return "", false
	}
	return identity.Namespace + "/" + identity.Name, true
}

func newTestInformerResolver(t *testing.T) (cache.SharedIndexInformer, *InformerResolver) {
	t.Helper()
	informer := cache.NewSharedIndexInformer(&cache.ListWatch{}, &v1.Pod{}, 0, cache.Indexers{})
	resolver, err := NewInformerResolver(informer)
	if err != nil {
		t.Fatalf("NewInformerResolver() returned an unexpected error: %v", err)
	}
	return informer, resolver
}

// --- InformerResolver Tests ---

func TestNewInformerResolver(t *testing.T) {
	informer := cache.NewSharedIndexInformer(
		&cache.ListWatch{},
		&v1.Pod{},
		0,
		cache.Indexers{},
	)
	_, err := NewInformerResolver(informer)
	if err != nil {
		t.Fatalf("NewInformerResolver() returned an unexpected error: %v", err)
	}

	if _, ok := informer.GetIndexer().GetIndexers()[PodIPIndex]; !ok {
		t.Fatal("NewInformerResolver() did not add the PodIPIndex to the informer")
	}
}

func TestInformerResolver_LookupPod(t *testing.T) {
	pod1 := makePod("ns1", "pod1", "10.0.0.1", v1.PodRunning, false)
	pod2 := makePod("ns1", "pod2", "10.0.0.2", v1.PodSucceeded, false)
	pod2Failed := makePod("ns1", "pod2-failed", "10.0.0.2", v1.PodFailed, false)
	pod6Pending := makePod("ns1", "pod6", "10.0.0.6", v1.PodPending, false)
	pod7Unknown := makePod("ns1", "pod7", "10.0.0.7", v1.PodUnknown, false)
	pod3Running := makePod("ns2", "pod3", "10.0.0.3", v1.PodRunning, false)
	pod3Pending := makePod("ns2", "pod3-pending", "10.0.0.3", v1.PodPending, false)
	pod4Host := makePod("ns1", "pod4-host", "10.0.0.4", v1.PodRunning, true)
	pod5MultiIP := makePodWithIPs("ns3", "pod5", []string{"10.0.0.5", "192.168.1.5"}, v1.PodRunning)

	tests := []struct {
		name       string
		pods       []*v1.Pod
		lookupIP   string
		expectedOk bool
		expected   string
	}{
		{
			name:       "found running pod",
			pods:       []*v1.Pod{pod1},
			lookupIP:   "10.0.0.1",
			expectedOk: true,
			expected:   "ns1/pod1",
		},
		{
			name:       "succeeded pod is not resolved",
			pods:       []*v1.Pod{pod2},
			lookupIP:   "10.0.0.2",
			expectedOk: false,
			expected:   "",
		},
		{
			name:       "failed pod is not resolved",
			pods:       []*v1.Pod{pod2Failed},
			lookupIP:   "10.0.0.2",
			expectedOk: false,
			expected:   "",
		},
		{
			name:       "found pending pod",
			pods:       []*v1.Pod{pod6Pending},
			lookupIP:   "10.0.0.6",
			expectedOk: true,
			expected:   "ns1/pod6",
		},
		{
			name:       "found unknown pod",
			pods:       []*v1.Pod{pod7Unknown},
			lookupIP:   "10.0.0.7",
			expectedOk: true,
			expected:   "ns1/pod7",
		},
		{
			name:       "ip not found",
			pods:       []*v1.Pod{pod1},
			lookupIP:   "1.2.3.4",
			expectedOk: false,
			expected:   "",
		},
		{
			name:       "multiple pods with same ip, one running",
			pods:       []*v1.Pod{pod3Running, pod3Pending},
			lookupIP:   "10.0.0.3",
			expectedOk: true,
			expected:   "ns2/pod3",
		},
		{
			name:       "host network pod ip is not indexed",
			pods:       []*v1.Pod{pod4Host},
			lookupIP:   "10.0.0.4",
			expectedOk: false,
			expected:   "",
		},
		{
			name:       "pod with multiple ips, found by first ip",
			pods:       []*v1.Pod{pod5MultiIP},
			lookupIP:   "10.0.0.5",
			expectedOk: true,
			expected:   "ns3/pod5",
		},
		{
			name:       "pod with multiple ips, found by second ip",
			pods:       []*v1.Pod{pod5MultiIP},
			lookupIP:   "192.168.1.5",
			expectedOk: true,
			expected:   "ns3/pod5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			informer := cache.NewSharedIndexInformer(&cache.ListWatch{}, &v1.Pod{}, 0, cache.Indexers{})
			resolver, err := NewInformerResolver(informer)
			if err != nil {
				t.Fatalf("NewInformerResolver() returned an unexpected error: %v", err)
			}

			for _, pod := range tt.pods {
				informer.GetIndexer().Add(pod)
			}

			key, ok := lookupKey(resolver, tt.lookupIP)
			if ok != tt.expectedOk {
				t.Errorf("LookupPod() ok = %v, want %v", ok, tt.expectedOk)
			}
			if key != tt.expected {
				t.Errorf("LookupPod() key = %q, want %q", key, tt.expected)
			}
		})
	}
}

func TestInformerResolver_LookupPod_RunningPodUpdatedToSucceeded(t *testing.T) {
	informer, resolver := newTestInformerResolver(t)

	pod := makePod("ns1", "job-pod", "10.0.0.10", v1.PodRunning, false)
	if err := informer.GetIndexer().Add(pod); err != nil {
		t.Fatalf("Add() failed: %v", err)
	}
	if key, ok := lookupKey(resolver, "10.0.0.10"); !ok || key != "ns1/job-pod" {
		t.Fatalf("LookupPod() before update got %q, %v; want %q, true", key, ok, "ns1/job-pod")
	}

	// The pod finishes but keeps its IPs in status.
	finished := pod.DeepCopy()
	finished.Status.Phase = v1.PodSucceeded
	if err := informer.GetIndexer().Update(finished); err != nil {
		t.Fatalf("Update() failed: %v", err)
	}

	if key, ok := lookupKey(resolver, "10.0.0.10"); ok || key != "" {
		t.Errorf("LookupPod() after pod succeeded got %q, %v; want %q, false", key, ok, "")
	}
}

func TestInformerResolver_LookupPod_PendingAndSucceededShareIP(t *testing.T) {
	informer, resolver := newTestInformerResolver(t)

	oldPod := makePod("ns1", "old-pod", "10.0.0.11", v1.PodSucceeded, false)
	newPod := makePod("ns1", "new-pod", "10.0.0.11", v1.PodPending, false)
	for _, pod := range []*v1.Pod{oldPod, newPod} {
		if err := informer.GetIndexer().Add(pod); err != nil {
			t.Fatalf("Add() failed: %v", err)
		}
	}

	objs, err := informer.GetIndexer().ByIndex(PodIPIndex, "10.0.0.11")
	if err != nil {
		t.Fatalf("ByIndex() returned an unexpected error: %v", err)
	}
	if len(objs) != 1 || objs[0].(*v1.Pod).Name != "new-pod" {
		names := make([]string, 0, len(objs))
		for _, obj := range objs {
			names = append(names, obj.(*v1.Pod).Name)
		}
		t.Fatalf("ByIndex() got pods %v, want only [new-pod]", names)
	}

	if key, ok := lookupKey(resolver, "10.0.0.11"); !ok || key != "ns1/new-pod" {
		t.Errorf("LookupPod() got %q, %v; want %q, true", key, ok, "ns1/new-pod")
	}
}

func deletingPod(pod *v1.Pod) *v1.Pod {
	now := metav1.Now()
	pod.DeletionTimestamp = &now
	return pod
}

// permutations returns every order of the pods.
func permutations(pods []*v1.Pod) [][]*v1.Pod {
	if len(pods) <= 1 {
		return [][]*v1.Pod{pods}
	}
	var result [][]*v1.Pod
	for i := range pods {
		rest := append(append([]*v1.Pod{}, pods[:i]...), pods[i+1:]...)
		for _, permutation := range permutations(rest) {
			result = append(result, append([]*v1.Pod{pods[i]}, permutation...))
		}
	}
	return result
}

func TestInformerResolver_LookupPod_PodBeingDeleted(t *testing.T) {
	for _, ip := range []string{"10.0.0.1", "fd00::1"} {
		t.Run(ip, func(t *testing.T) {
			informer, resolver := newTestInformerResolver(t)
			// The pod may still be using the IP while it terminates.
			pod := deletingPod(makePod("ns1", "pod1", ip, v1.PodRunning, false))
			if err := informer.GetIndexer().Add(pod); err != nil {
				t.Fatalf("Add() failed: %v", err)
			}

			if key, ok := lookupKey(resolver, ip); !ok || key != "ns1/pod1" {
				t.Errorf("LookupPod() got %q, %v; want %q, true", key, ok, "ns1/pod1")
			}
		})
	}
}

func TestInformerResolver_LookupPod_SharedIPPriority(t *testing.T) {
	tests := []struct {
		name string
		pods func(ip string) []*v1.Pod
		want string
	}{
		{
			// A pod being deleted still shows Running with its IPs after its
			// sandbox is gone, and the IP may belong to another pod.
			name: "pending pod over running pod being deleted",
			pods: func(ip string) []*v1.Pod {
				return []*v1.Pod{
					deletingPod(makePod("ns1", "old-pod", ip, v1.PodRunning, false)),
					makePod("ns1", "new-pod", ip, v1.PodPending, false),
				}
			},
			want: "ns1/new-pod",
		},
		{
			name: "running pod over pending pod",
			pods: func(ip string) []*v1.Pod {
				return []*v1.Pod{
					makePod("ns1", "running-pod", ip, v1.PodRunning, false),
					makePod("ns1", "pending-pod", ip, v1.PodPending, false),
				}
			},
			want: "ns1/running-pod",
		},
		{
			name: "running pod over running pod being deleted",
			pods: func(ip string) []*v1.Pod {
				return []*v1.Pod{
					deletingPod(makePod("ns1", "old-pod", ip, v1.PodRunning, false)),
					makePod("ns1", "new-pod", ip, v1.PodRunning, false),
				}
			},
			want: "ns1/new-pod",
		},
		{
			name: "running pod over pending pod, both being deleted",
			pods: func(ip string) []*v1.Pod {
				return []*v1.Pod{
					deletingPod(makePod("ns1", "running-pod", ip, v1.PodRunning, false)),
					deletingPod(makePod("ns1", "pending-pod", ip, v1.PodPending, false)),
				}
			},
			want: "ns1/running-pod",
		},
		{
			name: "pending pod over running pod being deleted and terminal pod",
			pods: func(ip string) []*v1.Pod {
				return []*v1.Pod{
					makePod("ns1", "finished-pod", ip, v1.PodSucceeded, false),
					deletingPod(makePod("ns1", "old-pod", ip, v1.PodRunning, false)),
					makePod("ns1", "new-pod", ip, v1.PodPending, false),
				}
			},
			want: "ns1/new-pod",
		},
		{
			name: "running pod being deleted over terminal pods",
			pods: func(ip string) []*v1.Pod {
				return []*v1.Pod{
					makePod("ns1", "succeeded-pod", ip, v1.PodSucceeded, false),
					makePod("ns1", "failed-pod", ip, v1.PodFailed, false),
					deletingPod(makePod("ns1", "old-pod", ip, v1.PodRunning, false)),
				}
			},
			want: "ns1/old-pod",
		},
	}

	for _, tt := range tests {
		for _, ip := range []string{"10.0.0.1", "fd00::1"} {
			for i, pods := range permutations(tt.pods(ip)) {
				t.Run(fmt.Sprintf("%s/%s/order %d", tt.name, ip, i), func(t *testing.T) {
					informer, resolver := newTestInformerResolver(t)
					for _, pod := range pods {
						if err := informer.GetIndexer().Add(pod); err != nil {
							t.Fatalf("Add() failed: %v", err)
						}
					}

					// ByIndex returns the pods in map order, look up several
					// times so the result can not depend on it.
					for range 10 {
						if key, ok := lookupKey(resolver, ip); !ok || key != tt.want {
							t.Fatalf("LookupPod() got %q, %v; want %q, true", key, ok, tt.want)
						}
					}
				})
			}
		}
	}
}
