package podinfo

import (
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"sigs.k8s.io/kube-network-policies/pkg/api"
)

// fakeNRIResolver stands for the NRI resolver: it knows which pod owns an IP
// and can build a PodInfo from the sandbox data.
type fakeNRIResolver struct {
	owners map[string]*v1.Pod
}

func (f *fakeNRIResolver) LookupPod(ip string) (string, bool) {
	pod, ok := f.owners[ip]
	if !ok {
		return "", false
	}
	return api.PodUID(pod), true
}

func (f *fakeNRIResolver) GetPodInfoByIP(ip string) (*api.PodInfo, bool) {
	pod, ok := f.owners[ip]
	if !ok {
		return nil, false
	}
	return &api.PodInfo{
		Name:      pod.Name,
		Namespace: &api.Namespace{Name: pod.Namespace},
		UID:       api.PodUID(pod),
		Labels:    map[string]string{"source": "nri"},
	}, true
}

func makePodWithUID(namespace, name string, uid types.UID, ip string, phase v1.PodPhase) *v1.Pod {
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			UID:       uid,
			Labels:    map[string]string{"source": "informer"},
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{{Name: "c", Ports: []v1.ContainerPort{{Name: "http", ContainerPort: 80, Protocol: v1.ProtocolTCP}}}},
		},
		Status: v1.PodStatus{Phase: phase},
	}
	if ip != "" {
		pod.Status.PodIPs = []v1.PodIP{{IP: ip}}
	}
	return pod
}

func TestInformerProvider_GetPodInfoByIP(t *testing.T) {
	tests := []struct {
		name string
		// pods in the informer
		pods []*v1.Pod
		// the pod NRI says owns 10.0.0.1, an empty pod means NRI does not
		// know the IP, nil disables NRI
		nri *v1.Pod
		// expected result for 10.0.0.1
		wantFound  bool
		wantName   string
		wantSource string
	}{
		{
			name:       "informer and NRI agree, informer details win",
			pods:       []*v1.Pod{makePodWithUID("ns", "web", "uid-1", "10.0.0.1", v1.PodRunning)},
			nri:        &v1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "web", UID: "uid-1"}},
			wantFound:  true,
			wantName:   "web",
			wantSource: "informer",
		},
		{
			name: "new pod not reported by the kubelet yet, finished pod still has the IP",
			pods: []*v1.Pod{
				makePodWithUID("ns", "job-old", "uid-old", "10.0.0.1", v1.PodSucceeded),
				makePodWithUID("ns", "web", "uid-1", "", v1.PodPending),
			},
			nri:        &v1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "web", UID: "uid-1"}},
			wantFound:  true,
			wantName:   "web",
			wantSource: "informer",
		},
		{
			name: "mirror pod of a static pod, NRI reports the static pod UID, informer details win",
			pods: []*v1.Pod{func() *v1.Pod {
				pod := makePodWithUID("ns", "static-node1", "mirror-uid", "10.0.0.1", v1.PodRunning)
				pod.Annotations = map[string]string{"kubernetes.io/config.mirror": "static-uid"}
				return pod
			}()},
			nri:        &v1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "static-node1", UID: "static-uid"}},
			wantFound:  true,
			wantName:   "static-node1",
			wantSource: "informer",
		},
		{
			name:       "pod not in the informer, NRI details are used",
			pods:       nil,
			nri:        &v1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "web", UID: "uid-1"}},
			wantFound:  true,
			wantName:   "web",
			wantSource: "nri",
		},
		{
			name:       "same name different UID, NRI details are used",
			pods:       []*v1.Pod{makePodWithUID("ns", "web-0", "uid-old", "10.0.0.1", v1.PodRunning)},
			nri:        &v1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "web-0", UID: "uid-new"}},
			wantFound:  true,
			wantName:   "web-0",
			wantSource: "nri",
		},
		{
			// The sandbox still exists, the runtime has not released the IP,
			// a packet from it is the last one of that pod.
			name:       "informer has the pod as terminal but the runtime still has its sandbox, NRI details are used",
			pods:       []*v1.Pod{makePodWithUID("ns", "job", "uid-1", "10.0.0.1", v1.PodSucceeded)},
			nri:        &v1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "job", UID: "uid-1"}},
			wantFound:  true,
			wantName:   "job",
			wantSource: "nri",
		},
		{
			name:       "NRI does not know the IP, informer index is used",
			pods:       []*v1.Pod{makePodWithUID("ns", "remote", "uid-1", "10.0.0.1", v1.PodRunning)},
			nri:        &v1.Pod{},
			wantFound:  true,
			wantName:   "remote",
			wantSource: "informer",
		},
		{
			name:       "NRI disabled, informer index is used",
			pods:       []*v1.Pod{makePodWithUID("ns", "web", "uid-1", "10.0.0.1", v1.PodRunning)},
			nri:        nil,
			wantFound:  true,
			wantName:   "web",
			wantSource: "informer",
		},
		{
			name:      "NRI disabled, finished pod does not own the IP",
			pods:      []*v1.Pod{makePodWithUID("ns", "job", "uid-1", "10.0.0.1", v1.PodFailed)},
			nri:       nil,
			wantFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			factory := informers.NewSharedInformerFactory(fake.NewSimpleClientset(), 0)
			podInformer := factory.Core().V1().Pods()
			nsInformer := factory.Core().V1().Namespaces()
			informerResolver, err := NewInformerResolver(podInformer.Informer())
			if err != nil {
				t.Fatal(err)
			}
			for _, pod := range tt.pods {
				if err := podInformer.Informer().GetIndexer().Add(pod); err != nil {
					t.Fatal(err)
				}
			}

			var local LocalResolver
			if tt.nri != nil {
				nri := &fakeNRIResolver{owners: map[string]*v1.Pod{}}
				if tt.nri.Name != "" {
					nri.owners["10.0.0.1"] = tt.nri
				}
				local = nri
			}
			provider, err := NewInformerProvider(podInformer, nsInformer, nil, local, []IPResolver{informerResolver})
			if err != nil {
				t.Fatal(err)
			}

			podInfo, found := provider.GetPodInfoByIP("10.0.0.1")
			if found != tt.wantFound {
				t.Fatalf("GetPodInfoByIP() found = %v, want %v (%v)", found, tt.wantFound, podInfo)
			}
			if !found {
				return
			}
			if podInfo.Name != tt.wantName {
				t.Errorf("GetPodInfoByIP() name = %q, want %q", podInfo.Name, tt.wantName)
			}
			if podInfo.Labels["source"] != tt.wantSource {
				t.Errorf("GetPodInfoByIP() source = %q, want %q", podInfo.Labels["source"], tt.wantSource)
			}
			if tt.wantSource == "informer" && len(podInfo.ContainerPorts) != 1 {
				t.Errorf("GetPodInfoByIP() container ports = %v, want the informer ports", podInfo.ContainerPorts)
			}
		})
	}
}
