package podinfo

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"sigs.k8s.io/kube-network-policies/pkg/api"
)

// staticResolver always resolves to the same pod, with the UID of makePod.
type staticResolver struct {
	key string
}

func (r staticResolver) LookupPod(ip string) (PodIdentity, bool) {
	namespace, name, _ := strings.Cut(r.key, "/")
	return PodIdentity{Namespace: namespace, Name: name, UID: types.UID(r.key)}, true
}

func newTestInformerProvider(t *testing.T, pods []*v1.Pod, resolvers []IPResolver) *InformerProvider {
	t.Helper()
	informersFactory := informers.NewSharedInformerFactory(fake.NewSimpleClientset(), 0)
	podInformer := informersFactory.Core().V1().Pods()
	nsInformer := informersFactory.Core().V1().Namespaces()
	for _, pod := range pods {
		if err := podInformer.Informer().GetIndexer().Add(pod); err != nil {
			t.Fatalf("Add() failed: %v", err)
		}
	}
	return NewInformerProvider(podInformer, nsInformer, nil, resolvers)
}

func TestInformerProvider_GetPodInfoByIP_TerminalPods(t *testing.T) {
	tests := []struct {
		name       string
		pod        *v1.Pod
		resolvers  []IPResolver
		expectedOk bool
	}{
		{
			name:       "resolver returns running pod",
			pod:        makePod("ns1", "pod1", "10.0.0.1", v1.PodRunning, false),
			resolvers:  []IPResolver{staticResolver{key: "ns1/pod1"}},
			expectedOk: true,
		},
		{
			name:       "resolver returns succeeded pod",
			pod:        makePod("ns1", "pod1", "10.0.0.1", v1.PodSucceeded, false),
			resolvers:  []IPResolver{staticResolver{key: "ns1/pod1"}},
			expectedOk: false,
		},
		{
			name:       "resolver returns failed pod",
			pod:        makePod("ns1", "pod1", "10.0.0.1", v1.PodFailed, false),
			resolvers:  []IPResolver{staticResolver{key: "ns1/pod1"}},
			expectedOk: false,
		},
		{
			name:       "no resolver finds running pod",
			pod:        makePod("ns1", "pod1", "10.0.0.1", v1.PodRunning, false),
			expectedOk: true,
		},
		{
			name:       "no resolver finds pending pod",
			pod:        makePod("ns1", "pod1", "10.0.0.1", v1.PodPending, false),
			expectedOk: true,
		},
		{
			name:       "no resolver ignores succeeded pod",
			pod:        makePod("ns1", "pod1", "10.0.0.1", v1.PodSucceeded, false),
			expectedOk: false,
		},
		{
			name:       "no resolver ignores failed pod",
			pod:        makePod("ns1", "pod1", "10.0.0.1", v1.PodFailed, false),
			expectedOk: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := newTestInformerProvider(t, []*v1.Pod{tt.pod}, tt.resolvers)

			podInfo, ok := provider.GetPodInfoByIP("10.0.0.1")
			if ok != tt.expectedOk {
				t.Fatalf("GetPodInfoByIP() ok = %v, want %v", ok, tt.expectedOk)
			}
			if ok && (podInfo.Namespace.Name != "ns1" || podInfo.Name != "pod1") {
				t.Errorf("GetPodInfoByIP() got %s/%s, want ns1/pod1", podInfo.Namespace.Name, podInfo.Name)
			}
		})
	}
}

func TestInformerProvider_GetPodInfoByIP_SkipsTerminalPodFromResolver(t *testing.T) {
	oldPod := makePod("ns1", "old-pod", "10.0.0.1", v1.PodSucceeded, false)
	newPod := makePod("ns1", "new-pod", "10.0.0.1", v1.PodPending, false)
	resolvers := []IPResolver{
		staticResolver{key: "ns1/old-pod"},
		staticResolver{key: "ns1/new-pod"},
	}
	provider := newTestInformerProvider(t, []*v1.Pod{oldPod, newPod}, resolvers)

	podInfo, ok := provider.GetPodInfoByIP("10.0.0.1")
	if !ok {
		t.Fatal("GetPodInfoByIP() ok = false, want true")
	}
	if podInfo.Namespace.Name != "ns1" || podInfo.Name != "new-pod" {
		t.Errorf("GetPodInfoByIP() got %s/%s, want ns1/new-pod", podInfo.Namespace.Name, podInfo.Name)
	}
}

func TestInformerProvider_GetPodInfoByIP_TerminalPodFromResolver(t *testing.T) {
	for _, phase := range []v1.PodPhase{v1.PodSucceeded, v1.PodFailed} {
		for _, ip := range []string{"10.0.0.1", "fd00::1"} {
			t.Run(fmt.Sprintf("%s/%s", phase, ip), func(t *testing.T) {
				// A resolver other than the informer index, like NRI, may
				// return a pod that the API server already marked as finished.
				oldPod := makePod("ns1", "old-pod", ip, phase, false)
				newPod := makePod("ns1", "new-pod", ip, v1.PodPending, false)
				resolvers := []IPResolver{
					staticResolver{key: "ns1/old-pod"},
					staticResolver{key: "ns1/new-pod"},
				}
				provider := newTestInformerProvider(t, []*v1.Pod{oldPod, newPod}, resolvers)

				podInfo, ok := provider.GetPodInfoByIP(ip)
				if !ok {
					t.Fatal("GetPodInfoByIP() ok = false, want true")
				}
				if podInfo.Namespace.Name != "ns1" || podInfo.Name != "new-pod" {
					t.Errorf("GetPodInfoByIP() got %s/%s, want ns1/new-pod", podInfo.Namespace.Name, podInfo.Name)
				}
			})
		}
	}
}

func TestInformerProvider_GetPodInfoByIP_PodBeingDeletedFromResolver(t *testing.T) {
	// Only terminal pods are skipped, a pod being deleted may still use the IP.
	pod := deletingPod(makePod("ns1", "pod1", "10.0.0.1", v1.PodRunning, false))
	provider := newTestInformerProvider(t, []*v1.Pod{pod}, []IPResolver{staticResolver{key: "ns1/pod1"}})

	podInfo, ok := provider.GetPodInfoByIP("10.0.0.1")
	if !ok {
		t.Fatal("GetPodInfoByIP() ok = false, want true")
	}
	if podInfo.Namespace.Name != "ns1" || podInfo.Name != "pod1" {
		t.Errorf("GetPodInfoByIP() got %s/%s, want ns1/pod1", podInfo.Namespace.Name, podInfo.Name)
	}
}

// fakeResolver returns the same identity for every IP and records the
// finished pods that it is told to release.
type fakeResolver struct {
	identity PodIdentity
	released []string
}

func (r *fakeResolver) LookupPod(ip string) (PodIdentity, bool) {
	return r.identity, r.identity.Name != ""
}

func (r *fakeResolver) ReleaseFinishedPod(ip string, identity PodIdentity) {
	r.released = append(r.released, ip+" "+identity.SandboxID+" "+string(identity.UID))
}

func TestInformerProvider_GetPodInfoByIP_ResolverIdentity(t *testing.T) {
	const ip = "10.0.0.1"
	// What the resolver knows about the pod when the informer does not have it.
	resolverInfo := &api.PodInfo{Name: "pod1", Namespace: &api.Namespace{Name: "ns1"}}
	identity := PodIdentity{Namespace: "ns1", Name: "pod1", UID: "ns1/pod1", SandboxID: "sandbox-1", PodInfo: resolverInfo}
	withoutUID := identity
	withoutUID.UID = ""
	withoutInfo := identity
	withoutInfo.PodInfo = nil
	withUID := func(pod *v1.Pod, uid types.UID) *v1.Pod {
		pod.UID = uid
		return pod
	}

	tests := []struct {
		name         string
		identity     PodIdentity
		pods         []*v1.Pod
		want         string // "informer", "resolver" or "" if not found
		wantReleased []string
	}{
		{
			name:     "informer pod with the same UID",
			identity: identity,
			pods:     []*v1.Pod{makePod("ns1", "pod1", ip, v1.PodPending, false)},
			want:     "informer",
		},
		{
			name:     "informer pod with another UID",
			identity: identity,
			pods:     []*v1.Pod{withUID(makePod("ns1", "pod1", ip, v1.PodRunning, false), "other")},
			want:     "resolver",
		},
		{
			name:     "pod not in the informer",
			identity: identity,
			want:     "resolver",
		},
		{
			name:     "resolver without UID",
			identity: withoutUID,
			pods:     []*v1.Pod{makePod("ns1", "pod1", ip, v1.PodRunning, false)},
			want:     "resolver",
		},
		{
			name:     "resolver without pod information",
			identity: withoutInfo,
			pods:     []*v1.Pod{withUID(makePod("ns1", "pod1", ip, v1.PodRunning, false), "other")},
			want:     "",
		},
		{
			name:         "terminal informer pod with the same UID",
			identity:     identity,
			pods:         []*v1.Pod{makePod("ns1", "pod1", ip, v1.PodSucceeded, false)},
			want:         "",
			wantReleased: []string{ip + " sandbox-1 ns1/pod1"},
		},
		{
			name:     "terminal informer pod with another UID",
			identity: identity,
			pods:     []*v1.Pod{withUID(makePod("ns1", "pod1", ip, v1.PodFailed, false), "other")},
			want:     "resolver",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := &fakeResolver{identity: tt.identity}
			provider := newTestInformerProvider(t, tt.pods, []IPResolver{resolver})

			podInfo, ok := provider.GetPodInfoByIP(ip)
			got := ""
			if ok && podInfo == resolverInfo {
				got = "resolver"
			} else if ok {
				got = "informer"
			}
			if got != tt.want {
				t.Errorf("GetPodInfoByIP() from %q, want %q", got, tt.want)
			}
			if !reflect.DeepEqual(resolver.released, tt.wantReleased) {
				t.Errorf("released pods = %v, want %v", resolver.released, tt.wantReleased)
			}
		})
	}
}
