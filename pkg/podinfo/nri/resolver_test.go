//go:build linux

package nri

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"testing"

	nriapi "github.com/containerd/nri/pkg/api"
	"sigs.k8s.io/kube-network-policies/pkg/api"
)

// --- Helpers ---

// selfNetns is a network namespace that always exists and can be opened
// without privileges, it stands for the netns of a running sandbox.
const selfNetns = "/proc/self/ns/net"

func makeNRIPod(namespace, name string, ips []string) *nriapi.PodSandbox {
	return makeNRISandbox(fmt.Sprintf("%s-%s", namespace, name), namespace, name, selfNetns, ips)
}

func makeNRISandbox(id, namespace, name, netnsPath string, ips []string) *nriapi.PodSandbox {
	return &nriapi.PodSandbox{
		Id:        id,
		Name:      name,
		Namespace: namespace,
		Uid:       id + "-uid",
		Ips:       ips,
		Linux: &nriapi.LinuxPodSandbox{
			Namespaces: []*nriapi.LinuxNamespace{
				{
					Type: "network",
					Path: netnsPath,
				},
			},
		},
	}
}

func newTestResolver() *NRIResolver {
	return &NRIResolver{
		podInfoByIP: make(map[string]*api.PodInfo),
		sandboxes:   make(map[string]*api.PodInfo),
	}
}

// expectLookup checks that the IP belongs to the pod of the sandbox.
func expectLookup(t *testing.T, resolver *NRIResolver, ip string, want *nriapi.PodSandbox) {
	t.Helper()
	wantKey := want.GetNamespace() + "/" + want.GetName()
	key, ok := resolver.LookupPod(ip)
	if !ok || key != wantKey {
		t.Errorf("LookupPod(%s) got %q, %v; want %q, true", ip, key, ok, wantKey)
	}
}

func expectNotFound(t *testing.T, resolver *NRIResolver, ip string) {
	t.Helper()
	if key, ok := resolver.LookupPod(ip); ok {
		t.Errorf("LookupPod(%s) got %q, want not found", ip, key)
	}
}

// --- NRIResolver Tests ---

func TestNRIResolver_PodLifecycle(t *testing.T) {
	ctx := context.Background()
	resolver := newTestResolver()

	pod1 := makeNRIPod("ns1", "pod1", []string{"10.0.0.1", "192.168.1.1"})
	if err := resolver.RunPodSandbox(ctx, pod1); err != nil {
		t.Fatalf("RunPodSandbox() failed for pod1: %v", err)
	}
	expectLookup(t, resolver, "10.0.0.1", pod1)
	expectLookup(t, resolver, "192.168.1.1", pod1)

	pod2 := makeNRIPod("ns2", "pod2", []string{"10.0.0.2"})
	if err := resolver.RunPodSandbox(ctx, pod2); err != nil {
		t.Fatalf("RunPodSandbox() failed for pod2: %v", err)
	}
	expectLookup(t, resolver, "10.0.0.2", pod2)

	// Stop releases the IPs, Remove is a no-op afterwards.
	if err := resolver.StopPodSandbox(ctx, pod1); err != nil {
		t.Fatalf("StopPodSandbox() failed for pod1: %v", err)
	}
	expectNotFound(t, resolver, "10.0.0.1")
	expectNotFound(t, resolver, "192.168.1.1")
	expectLookup(t, resolver, "10.0.0.2", pod2)
	if err := resolver.RemovePodSandbox(ctx, pod1); err != nil {
		t.Fatalf("RemovePodSandbox() failed for pod1: %v", err)
	}
	expectLookup(t, resolver, "10.0.0.2", pod2)

	// Remove without a previous Stop and without IPs in the event releases
	// the IPs too, see containerd/containerd#11331.
	pod2NoIPs := makeNRISandbox(pod2.Id, "ns2", "pod2", "", nil)
	if err := resolver.RemovePodSandbox(ctx, pod2NoIPs); err != nil {
		t.Fatalf("RemovePodSandbox() failed for pod2: %v", err)
	}
	expectNotFound(t, resolver, "10.0.0.2")
	if len(resolver.podInfoByIP) != 0 || len(resolver.sandboxes) != 0 {
		t.Errorf("state not empty after removing all sandboxes: byIP=%v sandboxes=%v", resolver.podInfoByIP, resolver.sandboxes)
	}
}

func TestNRIResolver_IPReuse(t *testing.T) {
	ctx := context.Background()
	resolver := newTestResolver()

	old := makeNRISandbox("sandbox-old", "ns1", "job-abc", selfNetns, []string{"10.0.0.1", "fd00::1"})
	if err := resolver.RunPodSandbox(ctx, old); err != nil {
		t.Fatalf("RunPodSandbox() failed: %v", err)
	}
	expectLookup(t, resolver, "10.0.0.1", old)

	// The runtime assigns the same IPs to a new sandbox, the Stop of the old
	// one may arrive later or never, see the Remove case below.
	newer := makeNRISandbox("sandbox-new", "ns2", "web", selfNetns, []string{"10.0.0.1", "fd00::1"})
	if err := resolver.RunPodSandbox(ctx, newer); err != nil {
		t.Fatalf("RunPodSandbox() failed: %v", err)
	}
	expectLookup(t, resolver, "10.0.0.1", newer)
	expectLookup(t, resolver, "fd00::1", newer)

	// A late Stop or Remove of the old sandbox does not touch the new owner.
	if err := resolver.StopPodSandbox(ctx, old); err != nil {
		t.Fatalf("StopPodSandbox() failed: %v", err)
	}
	expectLookup(t, resolver, "10.0.0.1", newer)
	expectLookup(t, resolver, "fd00::1", newer)
	if err := resolver.RemovePodSandbox(ctx, old); err != nil {
		t.Fatalf("RemovePodSandbox() failed: %v", err)
	}
	expectLookup(t, resolver, "10.0.0.1", newer)
	if _, ok := resolver.sandboxes["sandbox-old"]; ok {
		t.Error("old sandbox still tracked after Remove")
	}

	// The new owner releases its IPs normally.
	if err := resolver.StopPodSandbox(ctx, newer); err != nil {
		t.Fatalf("StopPodSandbox() failed: %v", err)
	}
	expectNotFound(t, resolver, "10.0.0.1")
	expectNotFound(t, resolver, "fd00::1")
}

// TestNRIResolver_RunTwice checks that a sandbox reported twice, which the
// runtime does not do today, does not leak the IPs of the first report. Every
// entry in podInfoByIP must belong to a sandbox or it is never released.
func TestNRIResolver_RunTwice(t *testing.T) {
	ctx := context.Background()
	resolver := newTestResolver()

	first := makeNRISandbox("sandbox-1", "ns1", "pod1", selfNetns, []string{"10.0.0.1", "fd00::1"})
	if err := resolver.RunPodSandbox(ctx, first); err != nil {
		t.Fatalf("RunPodSandbox() failed: %v", err)
	}
	second := makeNRISandbox("sandbox-1", "ns1", "pod1", selfNetns, []string{"10.0.0.2"})
	if err := resolver.RunPodSandbox(ctx, second); err != nil {
		t.Fatalf("RunPodSandbox() failed: %v", err)
	}
	expectNotFound(t, resolver, "10.0.0.1")
	expectNotFound(t, resolver, "fd00::1")
	expectLookup(t, resolver, "10.0.0.2", second)
	checkInvariant(t, resolver)

	if err := resolver.StopPodSandbox(ctx, second); err != nil {
		t.Fatalf("StopPodSandbox() failed: %v", err)
	}
	if len(resolver.podInfoByIP) != 0 || len(resolver.sandboxes) != 0 {
		t.Errorf("state not empty after stop: byIP=%v sandboxes=%v", resolver.podInfoByIP, resolver.sandboxes)
	}
}

// checkInvariant fails if an IP entry does not belong to a sandbox that
// lists that IP, that entry would never be released.
func checkInvariant(t *testing.T, resolver *NRIResolver) {
	t.Helper()
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	owned := make(map[string]*api.PodInfo)
	for _, podInfo := range resolver.sandboxes {
		for _, ip := range podInfo.IPs {
			owned[ip] = podInfo
		}
	}
	for ip, podInfo := range resolver.podInfoByIP {
		if owned[ip] != podInfo {
			t.Errorf("IP %s points to pod %s/%s that no sandbox owns", ip, podInfo.Namespace.Name, podInfo.Name)
		}
	}
}

func TestNRIResolver_Synchronize(t *testing.T) {
	ctx := context.Background()
	resolver := newTestResolver()

	// State before the runtime connection was lost.
	stale := makeNRISandbox("sandbox-stale", "ns1", "stale", selfNetns, []string{"10.0.0.9"})
	if err := resolver.RunPodSandbox(ctx, stale); err != nil {
		t.Fatalf("RunPodSandbox() failed: %v", err)
	}

	running := makeNRISandbox("sandbox-running", "ns1", "running", selfNetns, []string{"10.0.0.1"})
	// containerd 2.1+ reports the IPs of stopped sandboxes but their network
	// namespace is gone.
	stopped := makeNRISandbox("sandbox-stopped", "ns1", "stopped", "/var/run/netns/does-not-exist", []string{"10.0.0.1"})
	noNetns := makeNRISandbox("sandbox-nonetns", "ns1", "nonetns", "", []string{"10.0.0.2"})
	noIPs := makeNRISandbox("sandbox-noips", "ns1", "noips", "", nil)

	if _, err := resolver.Synchronize(ctx, []*nriapi.PodSandbox{stopped, running, noNetns, noIPs}, nil); err != nil {
		t.Fatalf("Synchronize() failed: %v", err)
	}

	expectLookup(t, resolver, "10.0.0.1", running)
	expectNotFound(t, resolver, "10.0.0.2")
	expectNotFound(t, resolver, "10.0.0.9")
	if len(resolver.sandboxes) != 1 {
		t.Errorf("Synchronize() kept %d sandboxes, want 1", len(resolver.sandboxes))
	}
	checkInvariant(t, resolver)
}

// TestNRIResolver_OnClose checks that the state is dropped when the
// connection to the runtime is lost, it goes stale without events.
func TestNRIResolver_OnClose(t *testing.T) {
	ctx := context.Background()
	resolver := newTestResolver()

	pod1 := makeNRIPod("ns1", "pod1", []string{"10.0.0.1"})
	if err := resolver.RunPodSandbox(ctx, pod1); err != nil {
		t.Fatalf("RunPodSandbox() failed: %v", err)
	}
	resolver.onClose()
	expectNotFound(t, resolver, "10.0.0.1")
	if len(resolver.sandboxes) != 0 {
		t.Errorf("sandboxes kept after the connection was lost: %v", resolver.sandboxes)
	}

	// The reconnection rebuilds the state.
	if _, err := resolver.Synchronize(ctx, []*nriapi.PodSandbox{pod1}, nil); err != nil {
		t.Fatalf("Synchronize() failed: %v", err)
	}
	expectLookup(t, resolver, "10.0.0.1", pod1)
}

func TestNRIResolver_Concurrent(t *testing.T) {
	ctx := context.Background()
	resolver := newTestResolver()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		ip := fmt.Sprintf("10.0.%d.1", i)
		old := makeNRISandbox(fmt.Sprintf("old-%d", i), "ns", fmt.Sprintf("old-%d", i), selfNetns, []string{ip})
		newer := makeNRISandbox(fmt.Sprintf("new-%d", i), "ns", fmt.Sprintf("new-%d", i), selfNetns, []string{ip})
		wg.Add(3)
		go func() {
			defer wg.Done()
			_ = resolver.RunPodSandbox(ctx, old)
			_ = resolver.RunPodSandbox(ctx, newer)
			_ = resolver.StopPodSandbox(ctx, old)
			_ = resolver.RemovePodSandbox(ctx, old)
		}()
		go func() {
			defer wg.Done()
			resolver.LookupPod(ip)
			resolver.GetPodInfoByIP(ip)
		}()
		go func() {
			defer wg.Done()
			_, _ = resolver.Synchronize(ctx, []*nriapi.PodSandbox{newer}, nil)
		}()
	}
	wg.Wait()
	checkInvariant(t, resolver)
}

func TestNRIResolver_LookupPod(t *testing.T) {
	resolver := newTestResolver()
	resolver.podInfoByIP["10.0.0.1"] = &api.PodInfo{Namespace: &api.Namespace{Name: "ns1"}, Name: "pod1"}

	key, ok := resolver.LookupPod("10.0.0.1")
	if !ok || key != "ns1/pod1" {
		t.Errorf("LookupPod() got %q, %v; want %q, true", key, ok, "ns1/pod1")
	}

	if key, ok = resolver.LookupPod("1.2.3.4"); ok {
		t.Errorf("LookupPod() got %q, want not found", key)
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
