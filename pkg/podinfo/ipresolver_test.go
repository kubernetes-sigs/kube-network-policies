package podinfo

import (
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

// --- Helpers ---

func makePod(namespace, name, ip string, phase v1.PodPhase, hostNetwork bool) *v1.Pod {
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Spec: v1.PodSpec{
			HostNetwork: hostNetwork,
		},
		Status: v1.PodStatus{
			Phase:  phase,
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
		},
		Status: v1.PodStatus{
			Phase:  phase,
			PodIPs: podIPs,
		},
	}
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
			name:       "found non-running pod",
			pods:       []*v1.Pod{pod2},
			lookupIP:   "10.0.0.2",
			expectedOk: true,
			expected:   "ns1/pod2",
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

			key, ok := resolver.LookupPod(tt.lookupIP)
			if ok != tt.expectedOk {
				t.Errorf("LookupPod() ok = %v, want %v", ok, tt.expectedOk)
			}
			if key != tt.expected {
				t.Errorf("LookupPod() key = %q, want %q", key, tt.expected)
			}
		})
	}
}
