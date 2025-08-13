package podinfo

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	nriapi "github.com/containerd/nri/pkg/api"
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

func makeNRIPod(namespace, name string, ips []string) *nriapi.PodSandbox {
	return &nriapi.PodSandbox{
		Id:        fmt.Sprintf("%s-%s", namespace, name),
		Name:      name,
		Namespace: namespace,
		Ips:       ips,
		Linux: &nriapi.LinuxPodSandbox{
			Namespaces: []*nriapi.LinuxNamespace{
				{
					Type: "network",
					Path: fmt.Sprintf("/var/run/netns/%s-%s", namespace, name),
				},
			},
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

// --- NRIResolver Tests ---

// Note: Testing NewNRIResolver is non-trivial as it involves a live NRI stub.
// We will test the internal logic of the resolver's methods instead.

func TestNRIResolver_PodLifecycle(t *testing.T) {
	resolver := &NRIResolver{podIPMap: make(map[string]string)}

	// 1. Add a pod
	pod1 := makeNRIPod("ns1", "pod1", []string{"10.0.0.1", "192.168.1.1"})
	if err := resolver.RunPodSandbox(context.Background(), pod1); err != nil {
		t.Fatalf("RunPodSandbox() failed for pod1: %v", err)
	}

	key, ok := resolver.LookupPod("10.0.0.1")
	if !ok || key != "ns1/pod1" {
		t.Errorf("LookupPod(10.0.0.1) got %q, %v; want %q, true", key, ok, "ns1/pod1")
	}

	key, ok = resolver.LookupPod("192.168.1.1")
	if !ok || key != "ns1/pod1" {
		t.Errorf("LookupPod(192.168.1.1) got %q, %v; want %q, true", key, ok, "ns1/pod1")
	}

	// 2. Add another pod
	pod2 := makeNRIPod("ns2", "pod2", []string{"10.0.0.2"})
	if err := resolver.RunPodSandbox(context.Background(), pod2); err != nil {
		t.Fatalf("RunPodSandbox() failed for pod2: %v", err)
	}

	key, ok = resolver.LookupPod("10.0.0.2")
	if !ok || key != "ns2/pod2" {
		t.Errorf("LookupPod(10.0.0.2) got %q, %v; want %q, true", key, ok, "ns2/pod2")
	}

	// 3. Synchronize state
	resolver.podIPMap = make(map[string]string) // Clear map
	pod3 := makeNRIPod("ns3", "pod3", []string{"10.0.0.3"})
	
	if _, err := resolver.Synchronize(context.Background(), []*nriapi.PodSandbox{pod1, pod2, pod3}, nil); err != nil {
		t.Fatalf("Synchronize() failed: %v", err)
	}

	if len(resolver.podIPMap) != 4 {
		t.Errorf("After Synchronize, map length is %d, want 4", len(resolver.podIPMap))
	}
	key, ok = resolver.LookupPod("10.0.0.3")
	if !ok || key != "ns3/pod3" {
		t.Errorf("LookupPod(10.0.0.3) after sync got %q, %v; want %q, true", key, ok, "ns3/pod3")
	}

	// 4. Remove a pod
	if err := resolver.RemovePodSandbox(context.Background(), pod1); err != nil {
		t.Fatalf("RemovePodSandbox() failed for pod1: %v", err)
	}

	if _, ok := resolver.LookupPod("10.0.0.1"); ok {
		t.Error("LookupPod(10.0.0.1) should have failed after removal")
	}
	if _, ok := resolver.LookupPod("192.168.1.1"); ok {
		t.Error("LookupPod(192.168.1.1) should have failed after removal")
	}

	// Check that other pod is still there
	key, ok = resolver.LookupPod("10.0.0.2")
	if !ok || key != "ns2/pod2" {
		t.Errorf("LookupPod(10.0.0.2) after removal got %q, %v; want %q, true", key, ok, "ns2/pod2")
	}

	// 5. Test removing pod by key fallback
	resolver.podIPMap["10.0.0.2"] = "ns2/pod2" // ensure it's there
	pod2NoIPs := makeNRIPod("ns2", "pod2", nil) // Simulate missing IPs on remove
	if err := resolver.RemovePodSandbox(context.Background(), pod2NoIPs); err != nil {
		t.Fatalf("RemovePodSandbox() with no IPs failed: %v", err)
	}
	if _, ok := resolver.LookupPod("10.0.0.2"); ok {
		t.Error("LookupPod(10.0.0.2) should have failed after fallback removal")
	}
}

func TestNRIResolver_LookupPod(t *testing.T) {
	resolver := &NRIResolver{
		podIPMap: map[string]string{
			"10.0.0.1": "ns1/pod1",
			"10.0.0.2": "ns2/pod2",
		},
	}

	// Test found
	key, ok := resolver.LookupPod("10.0.0.1")
	if !ok || key != "ns1/pod1" {
		t.Errorf("LookupPod() got key %q, ok %v; want %q, true", key, ok, "ns1/pod1")
	}

	// Test not found
	key, ok = resolver.LookupPod("1.2.3.4")
	if ok || key != "" {
		t.Errorf("LookupPod() got key %q, ok %v; want %q, false", key, ok, "")
	}
}

// --- Helper Function Tests ---

func TestGetPodIPs(t *testing.T) {
	// Note: Testing the netns/netlink fallback path is an integration test
	// and is out of scope for this unit test. We only test the primary path.
	t.Run("primary path with pod.GetIps()", func(t *testing.T) {
		expectedIPs := []string{"10.0.0.1", "192.168.1.1"}
		pod := &nriapi.PodSandbox{
			Ips: expectedIPs,
		}
		ips := getPodIPs(pod)
		if !reflect.DeepEqual(ips, expectedIPs) {
			t.Errorf("getPodIPs() got %v, want %v", ips, expectedIPs)
		}
	})

	t.Run("empty ips from pod.GetIps()", func(t *testing.T) {
		// This will try to use the fallback path, which will fail in a unit
		// test environment, but we expect it to return an empty slice gracefully.
		pod := &nriapi.PodSandbox{
			Ips: []string{},
			Linux: &nriapi.LinuxPodSandbox{
				Namespaces: []*nriapi.LinuxNamespace{
					{Type: "network", Path: "/dev/null/nonexistent"},
				},
			},
		}
		ips := getPodIPs(pod)
		if len(ips) != 0 {
			t.Errorf("getPodIPs() expected empty slice, got %v", ips)
		}
	})
}
