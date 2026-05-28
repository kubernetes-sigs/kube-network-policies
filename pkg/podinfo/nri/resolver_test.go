//go:build linux

package nri

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	nriapi "github.com/containerd/nri/pkg/api"
	"sigs.k8s.io/kube-network-policies/pkg/api"
)

// --- Helpers ---

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

// --- NRIResolver Tests ---

func TestNRIResolver_PodLifecycle(t *testing.T) {
	resolver := &NRIResolver{podInfoByIP: make(map[string]*api.PodInfo)}

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
	resolver.podInfoByIP = make(map[string]*api.PodInfo) // Clear map
	pod3 := makeNRIPod("ns3", "pod3", []string{"10.0.0.3"})

	if _, err := resolver.Synchronize(context.Background(), []*nriapi.PodSandbox{pod1, pod2, pod3}, nil); err != nil {
		t.Fatalf("Synchronize() failed: %v", err)
	}

	if len(resolver.podInfoByIP) != 4 {
		t.Errorf("After Synchronize, map length is %d, want 4", len(resolver.podInfoByIP))
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
}

func TestNRIResolver_LookupPod(t *testing.T) {
	resolver := &NRIResolver{
		podInfoByIP: map[string]*api.PodInfo{
			"10.0.0.1": {Namespace: &api.Namespace{Name: "ns1"}, Name: "pod1"},
			"10.0.0.2": {Namespace: &api.Namespace{Name: "ns2"}, Name: "pod2"},
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
