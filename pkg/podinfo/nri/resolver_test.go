//go:build linux

package nri

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	nriapi "github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/kube-network-policies/pkg/podinfo"
)

// --- Helpers ---

// liveNetNS is a network namespace that exists and can be opened without privileges.
const liveNetNS = "/proc/self/ns/net"

func makeNRIPod(namespace, name string, ips []string) *nriapi.PodSandbox {
	return &nriapi.PodSandbox{
		Id:        fmt.Sprintf("%s-%s", namespace, name),
		Name:      name,
		Namespace: namespace,
		Ips:       ips,
		Linux:     networkNamespace(liveNetNS),
	}
}

func networkNamespace(path string) *nriapi.LinuxPodSandbox {
	return &nriapi.LinuxPodSandbox{
		Namespaces: []*nriapi.LinuxNamespace{{Type: "network", Path: path}},
	}
}

// sandboxIDLabel records the sandbox ID in the test sandbox labels, so lookups
// can tell which sandbox owns an IP even when two sandboxes belong to the same Pod.
const sandboxIDLabel = "test.sandbox-id"

func newTestResolver() *NRIResolver {
	return &NRIResolver{
		sandboxes: make(map[string]*sandboxRecord),
		ipOwners:  make(map[string]string),
		stopped:   sets.New[string](),
	}
}

// makeSandbox returns a running sandbox: if it has IPs, its network namespace exists.
func makeSandbox(id, uid, namespace, name string, ips ...string) *nriapi.PodSandbox {
	sandbox := &nriapi.PodSandbox{
		Id:        id,
		Uid:       uid,
		Name:      name,
		Namespace: namespace,
		Labels:    map[string]string{sandboxIDLabel: id},
		Ips:       ips,
	}
	if len(ips) > 0 {
		sandbox.Linux = networkNamespace(liveNetNS)
	}
	return sandbox
}

// idOnly returns an event for the sandbox without IPs nor network namespace,
// the runtime may not include them in StopPodSandbox and RemovePodSandbox.
func idOnly(sandbox *nriapi.PodSandbox) *nriapi.PodSandbox {
	return makeSandbox(sandbox.Id, sandbox.Uid, sandbox.Namespace, sandbox.Name)
}

// stopSandbox delivers a StopPodSandbox event. The NRI stub only delivers the
// event to plugins implementing stub.StopPodInterface, so the test fails if
// the resolver does not.
func stopSandbox(t *testing.T, resolver *NRIResolver, sandbox *nriapi.PodSandbox) {
	t.Helper()
	handler, ok := any(resolver).(stub.StopPodInterface)
	if !ok {
		t.Errorf("NRIResolver does not handle StopPodSandbox events")
		return
	}
	if err := handler.StopPodSandbox(context.Background(), sandbox); err != nil {
		t.Fatalf("StopPodSandbox(%s) failed: %v", sandbox.Id, err)
	}
}

// sandboxOwner returns the ID of the sandbox that owns ip, or "" if none does.
func sandboxOwner(t *testing.T, resolver *NRIResolver, ip string) string {
	t.Helper()
	podInfo, ok := resolver.GetPodInfoByIP(ip)
	if !ok {
		return ""
	}
	return podInfo.Labels[sandboxIDLabel]
}

func runSandboxes(t *testing.T, resolver *NRIResolver, sandboxes ...*nriapi.PodSandbox) {
	t.Helper()
	for _, sandbox := range sandboxes {
		if err := resolver.RunPodSandbox(context.Background(), sandbox); err != nil {
			t.Fatalf("RunPodSandbox(%s) failed: %v", sandbox.Id, err)
		}
	}
}

func removeSandbox(t *testing.T, resolver *NRIResolver, sandbox *nriapi.PodSandbox) {
	t.Helper()
	if err := resolver.RemovePodSandbox(context.Background(), sandbox); err != nil {
		t.Fatalf("RemovePodSandbox(%s) failed: %v", sandbox.Id, err)
	}
}

func synchronize(t *testing.T, resolver *NRIResolver, sandboxes ...*nriapi.PodSandbox) {
	t.Helper()
	if _, err := resolver.Synchronize(context.Background(), sandboxes, nil); err != nil {
		t.Fatalf("Synchronize() failed: %v", err)
	}
}

func assertOwner(t *testing.T, resolver *NRIResolver, ip, want string) {
	t.Helper()
	if got := sandboxOwner(t, resolver, ip); got != want {
		t.Errorf("owner of %s = %q, want %q", ip, got, want)
	}
}

// --- NRIResolver Tests ---

func TestNRIResolver_PodLifecycle(t *testing.T) {
	resolver := newTestResolver()

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

	// 3. Synchronize state, the snapshot replaces the cache
	pod3 := makeNRIPod("ns3", "pod3", []string{"10.0.0.3"})

	if _, err := resolver.Synchronize(context.Background(), []*nriapi.PodSandbox{pod1, pod2, pod3}, nil); err != nil {
		t.Fatalf("Synchronize() failed: %v", err)
	}

	if len(resolver.ipOwners) != 4 {
		t.Errorf("After Synchronize, map length is %d, want 4", len(resolver.ipOwners))
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
	resolver := newTestResolver()
	runSandboxes(t, resolver,
		makeNRIPod("ns1", "pod1", []string{"10.0.0.1"}),
		makeNRIPod("ns2", "pod2", []string{"10.0.0.2"}),
	)

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

// failOnPanic reports a panic as a test failure so the remaining tests still run.
func failOnPanic(t *testing.T) {
	t.Helper()
	if r := recover(); r != nil {
		t.Fatalf("unexpected panic: %v", r)
	}
}

func TestNRIResolver_NilReceiver(t *testing.T) {
	// NewNRIResolver returns a nil resolver when the NRI plugin can not be created.
	var resolver *NRIResolver

	t.Run("LookupPod", func(t *testing.T) {
		defer failOnPanic(t)
		key, ok := resolver.LookupPod("10.0.0.1")
		if ok || key != "" {
			t.Errorf("LookupPod() got key %q, ok %v; want %q, false", key, ok, "")
		}
	})

	t.Run("GetPodInfoByIP", func(t *testing.T) {
		defer failOnPanic(t)
		podInfo, ok := resolver.GetPodInfoByIP("10.0.0.1")
		if ok || podInfo != nil {
			t.Errorf("GetPodInfoByIP() got %v, ok %v; want nil, false", podInfo, ok)
		}
	})

	t.Run("typed nil IPResolver", func(t *testing.T) {
		defer failOnPanic(t)
		var ipResolver podinfo.IPResolver = resolver
		key, ok := ipResolver.LookupPod("10.0.0.1")
		if ok || key != "" {
			t.Errorf("LookupPod() got key %q, ok %v; want %q, false", key, ok, "")
		}
	})
}

func TestNRIResolver_LookupPodThroughIPResolver(t *testing.T) {
	resolver := newTestResolver()
	runSandboxes(t, resolver, makeNRIPod("ns1", "pod1", []string{"10.0.0.1"}))
	var ipResolver podinfo.IPResolver = resolver

	key, ok := ipResolver.LookupPod("10.0.0.1")
	if !ok || key != "ns1/pod1" {
		t.Errorf("LookupPod() got key %q, ok %v; want %q, true", key, ok, "ns1/pod1")
	}

	key, ok = ipResolver.LookupPod("1.2.3.4")
	if ok || key != "" {
		t.Errorf("LookupPod() got key %q, ok %v; want %q, false", key, ok, "")
	}
}

// --- Sandbox IP ownership tests ---

// Removing a sandbox must only release the IPs that it still owns. A removal
// event can arrive long after the sandbox stopped and its IPs were reused.

func TestNRIResolver_RemoveOwnSandbox(t *testing.T) {
	resolver := newTestResolver()
	sandboxA := makeSandbox("sandbox-a", "uid-a", "ns1", "pod-a", "10.0.0.1")
	sandboxB := makeSandbox("sandbox-b", "uid-b", "ns1", "pod-b", "10.0.0.2")
	runSandboxes(t, resolver, sandboxA, sandboxB)

	removeSandbox(t, resolver, sandboxA)

	assertOwner(t, resolver, "10.0.0.1", "")
	assertOwner(t, resolver, "10.0.0.2", "sandbox-b")
}

func TestNRIResolver_RemoveAfterIPReuse(t *testing.T) {
	resolver := newTestResolver()
	sandboxA := makeSandbox("sandbox-a", "uid-a", "ns1", "pod-a", "10.0.0.1")
	sandboxB := makeSandbox("sandbox-b", "uid-b", "ns1", "pod-b", "10.0.0.1")
	runSandboxes(t, resolver, sandboxA, sandboxB)

	removeSandbox(t, resolver, sandboxA)

	assertOwner(t, resolver, "10.0.0.1", "sandbox-b")
}

func TestNRIResolver_RemoveWithoutIPs(t *testing.T) {
	resolver := newTestResolver()
	sandboxA := makeSandbox("sandbox-a", "uid-a", "ns1", "pod-a", "10.0.0.1")
	sandboxB := makeSandbox("sandbox-b", "uid-b", "ns1", "pod-b", "10.0.0.2")
	runSandboxes(t, resolver, sandboxA, sandboxB)

	// The runtime may not report the IPs on removal and the network namespace
	// may already be gone, https://github.com/containerd/containerd/pull/11331
	removal := makeSandbox("sandbox-a", "uid-a", "ns1", "pod-a")
	removal.Linux = &nriapi.LinuxPodSandbox{
		Namespaces: []*nriapi.LinuxNamespace{
			{Type: "network", Path: "/var/run/netns/nonexistent-sandbox-a"},
		},
	}
	removeSandbox(t, resolver, removal)

	assertOwner(t, resolver, "10.0.0.1", "")
	assertOwner(t, resolver, "10.0.0.2", "sandbox-b")
}

func TestNRIResolver_RemoveAfterDualStackIPReuse(t *testing.T) {
	resolver := newTestResolver()
	sandboxA := makeSandbox("sandbox-a", "uid-a", "ns1", "pod-a", "10.0.0.1", "fd00::1")
	sandboxB := makeSandbox("sandbox-b", "uid-b", "ns1", "pod-b", "10.0.0.1", "fd00::1")
	runSandboxes(t, resolver, sandboxA, sandboxB)

	removeSandbox(t, resolver, sandboxA)

	assertOwner(t, resolver, "10.0.0.1", "sandbox-b")
	assertOwner(t, resolver, "fd00::1", "sandbox-b")
}

func TestNRIResolver_RemoveSynchronizedSandboxAfterIPReuse(t *testing.T) {
	resolver := newTestResolver()
	sandboxA := makeSandbox("sandbox-a", "uid-a", "ns1", "pod-a", "10.0.0.1")
	sandboxB := makeSandbox("sandbox-b", "uid-b", "ns1", "pod-b", "10.0.0.1")
	synchronize(t, resolver, sandboxA)
	runSandboxes(t, resolver, sandboxB)

	removeSandbox(t, resolver, sandboxA)

	assertOwner(t, resolver, "10.0.0.1", "sandbox-b")
}

func TestNRIResolver_SynchronizeDropsRemovedSandboxes(t *testing.T) {
	t.Run("empty snapshot", func(t *testing.T) {
		resolver := newTestResolver()
		synchronize(t, resolver, makeSandbox("sandbox-a", "uid-a", "ns1", "pod-a", "10.0.0.1"))

		synchronize(t, resolver)

		assertOwner(t, resolver, "10.0.0.1", "")
	})

	t.Run("sandbox missing from snapshot", func(t *testing.T) {
		resolver := newTestResolver()
		sandboxA := makeSandbox("sandbox-a", "uid-a", "ns1", "pod-a", "10.0.0.1")
		sandboxB := makeSandbox("sandbox-b", "uid-b", "ns1", "pod-b", "10.0.0.2")
		synchronize(t, resolver, sandboxA, sandboxB)

		synchronize(t, resolver, sandboxB)

		assertOwner(t, resolver, "10.0.0.1", "")
		assertOwner(t, resolver, "10.0.0.2", "sandbox-b")
	})
}

func TestNRIResolver_RemoveReplacedSandboxOfSamePod(t *testing.T) {
	resolver := newTestResolver()
	// The kubelet creates a new sandbox for the same Pod, and the network
	// plugin hands out the same IP, before the old sandbox is removed.
	sandboxA := makeSandbox("sandbox-a", "uid-1", "ns1", "web-0", "10.0.0.1")
	sandboxB := makeSandbox("sandbox-b", "uid-1", "ns1", "web-0", "10.0.0.1")
	runSandboxes(t, resolver, sandboxA, sandboxB)

	removeSandbox(t, resolver, sandboxA)

	assertOwner(t, resolver, "10.0.0.1", "sandbox-b")
}

func TestNRIResolver_RunPodSandboxAgainWithNewIPs(t *testing.T) {
	t.Run("previous IPs are released", func(t *testing.T) {
		resolver := newTestResolver()
		runSandboxes(t, resolver, makeSandbox("sandbox-a", "uid-a", "ns1", "pod-a", "10.0.0.1", "fd00::1"))

		runSandboxes(t, resolver, makeSandbox("sandbox-a", "uid-a", "ns1", "pod-a", "10.0.0.2"))

		assertOwner(t, resolver, "10.0.0.1", "")
		assertOwner(t, resolver, "fd00::1", "")
		assertOwner(t, resolver, "10.0.0.2", "sandbox-a")
	})

	t.Run("IPs reused by another sandbox are kept", func(t *testing.T) {
		resolver := newTestResolver()
		runSandboxes(t, resolver,
			makeSandbox("sandbox-a", "uid-a", "ns1", "pod-a", "10.0.0.1"),
			makeSandbox("sandbox-b", "uid-b", "ns1", "pod-b", "10.0.0.1"),
		)

		runSandboxes(t, resolver, makeSandbox("sandbox-a", "uid-a", "ns1", "pod-a", "10.0.0.2"))

		assertOwner(t, resolver, "10.0.0.1", "sandbox-b")
		assertOwner(t, resolver, "10.0.0.2", "sandbox-a")
	})
}

// The runtime snapshot includes stopped sandboxes with the IPs they had, so two
// sandboxes can claim the same IP and the snapshot does not tell which one is
// running. The IP must not resolve until its ownership is established.

func TestNRIResolver_SynchronizeConflictingClaims(t *testing.T) {
	for _, order := range []string{"A then B", "B then A"} {
		t.Run(order, func(t *testing.T) {
			resolver := newTestResolver()
			sandboxA := makeSandbox("sandbox-a", "uid-a", "ns1", "pod-a", "10.0.0.1", "fd00::1")
			sandboxB := makeSandbox("sandbox-b", "uid-b", "ns1", "pod-b", "10.0.0.1", "fd00::1", "10.0.0.2")
			snapshot := []*nriapi.PodSandbox{sandboxA, sandboxB}
			if order == "B then A" {
				snapshot = []*nriapi.PodSandbox{sandboxB, sandboxA}
			}

			synchronize(t, resolver, snapshot...)

			assertOwner(t, resolver, "10.0.0.1", "")
			assertOwner(t, resolver, "fd00::1", "")
			assertOwner(t, resolver, "10.0.0.2", "sandbox-b")
		})
	}
}

func TestNRIResolver_ResolveConflictingClaims(t *testing.T) {
	sandboxA := makeSandbox("sandbox-a", "uid-a", "ns1", "pod-a", "10.0.0.1")
	sandboxB := makeSandbox("sandbox-b", "uid-b", "ns1", "pod-b", "10.0.0.1")

	t.Run("RunPodSandbox claims the IP", func(t *testing.T) {
		resolver := newTestResolver()
		synchronize(t, resolver, sandboxB, sandboxA)
		assertOwner(t, resolver, "10.0.0.1", "")

		runSandboxes(t, resolver, sandboxB)

		assertOwner(t, resolver, "10.0.0.1", "sandbox-b")
	})

	t.Run("snapshot without the conflict", func(t *testing.T) {
		resolver := newTestResolver()
		synchronize(t, resolver, sandboxB, sandboxA)
		assertOwner(t, resolver, "10.0.0.1", "")

		synchronize(t, resolver, sandboxB)

		assertOwner(t, resolver, "10.0.0.1", "sandbox-b")
	})

	t.Run("removing a claimant does not pick the other one", func(t *testing.T) {
		resolver := newTestResolver()
		synchronize(t, resolver, sandboxA, sandboxB)

		// The remaining claimant may be the stopped sandbox, so its claim is
		// not proven by the removal of the other one.
		removeSandbox(t, resolver, makeSandbox("sandbox-a", "uid-a", "ns1", "pod-a"))

		assertOwner(t, resolver, "10.0.0.1", "")
	})
}

func TestNRIResolver_ConcurrentLifecycle(t *testing.T) {
	resolver := newTestResolver()
	synced := makeSandbox("sandbox-synced", "uid-synced", "ns1", "pod-synced", "10.0.1.1")

	var wg sync.WaitGroup
	for i := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ip := fmt.Sprintf("10.0.0.%d", i+1)
			sandbox := makeSandbox(fmt.Sprintf("sandbox-%d", i), fmt.Sprintf("uid-%d", i), "ns1", fmt.Sprintf("pod-%d", i), ip)
			for range 100 {
				_ = resolver.RunPodSandbox(context.Background(), sandbox)
				resolver.LookupPod(ip)
				_ = resolver.StopPodSandbox(context.Background(), sandbox)
				_ = resolver.RemovePodSandbox(context.Background(), sandbox)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 100 {
			_, _ = resolver.Synchronize(context.Background(), []*nriapi.PodSandbox{synced}, nil)
			resolver.LookupPod("10.0.1.1")
		}
	}()
	wg.Wait()

	// Every worker removed its sandbox last, and the snapshots only had the synced sandbox.
	for i := range 4 {
		assertOwner(t, resolver, fmt.Sprintf("10.0.0.%d", i+1), "")
	}
	assertOwner(t, resolver, "10.0.1.1", "sandbox-synced")
	if resolver.stopped.Len() != 0 {
		t.Errorf("stopped sandboxes = %v, want none", sets.List(resolver.stopped))
	}
}

// --- Sandbox lifecycle tests ---

// The runtime sends StopPodSandbox when it stops the sandbox, before it tears
// down its network and releases the IPs, and again on every stop request and
// before removing the sandbox.

func TestNRIResolver_StopPodSandbox(t *testing.T) {
	sandboxA := makeSandbox("sandbox-a", "uid-a", "ns1", "pod-a", "10.0.0.1", "fd00::1")
	sandboxB := makeSandbox("sandbox-b", "uid-b", "ns1", "pod-b", "10.0.0.1", "fd00::1")

	t.Run("stopped sandbox does not own its IPs", func(t *testing.T) {
		resolver := newTestResolver()
		runSandboxes(t, resolver, sandboxA)

		stopSandbox(t, resolver, sandboxA)

		assertOwner(t, resolver, "10.0.0.1", "")
		assertOwner(t, resolver, "fd00::1", "")
	})

	t.Run("stop event without IPs", func(t *testing.T) {
		resolver := newTestResolver()
		runSandboxes(t, resolver, sandboxA)

		stopSandbox(t, resolver, idOnly(sandboxA))

		assertOwner(t, resolver, "10.0.0.1", "")
		assertOwner(t, resolver, "fd00::1", "")
	})

	t.Run("late stop and remove after IP reuse", func(t *testing.T) {
		resolver := newTestResolver()
		runSandboxes(t, resolver, sandboxA, sandboxB)

		stopSandbox(t, resolver, sandboxA)
		assertOwner(t, resolver, "10.0.0.1", "sandbox-b")
		assertOwner(t, resolver, "fd00::1", "sandbox-b")

		removeSandbox(t, resolver, sandboxA)
		assertOwner(t, resolver, "10.0.0.1", "sandbox-b")
		assertOwner(t, resolver, "fd00::1", "sandbox-b")
	})

	t.Run("late stop and remove without IPs after IP reuse", func(t *testing.T) {
		resolver := newTestResolver()
		runSandboxes(t, resolver, sandboxA, sandboxB)

		stopSandbox(t, resolver, idOnly(sandboxA))
		removeSandbox(t, resolver, idOnly(sandboxA))

		assertOwner(t, resolver, "10.0.0.1", "sandbox-b")
		assertOwner(t, resolver, "fd00::1", "sandbox-b")
	})

	t.Run("IP reused after stop", func(t *testing.T) {
		resolver := newTestResolver()
		runSandboxes(t, resolver, sandboxA)
		stopSandbox(t, resolver, sandboxA)

		runSandboxes(t, resolver, sandboxB)
		stopSandbox(t, resolver, sandboxA)
		removeSandbox(t, resolver, sandboxA)

		assertOwner(t, resolver, "10.0.0.1", "sandbox-b")
		assertOwner(t, resolver, "fd00::1", "sandbox-b")
	})

	t.Run("repeated stop and remove", func(t *testing.T) {
		resolver := newTestResolver()
		sandboxC := makeSandbox("sandbox-c", "uid-c", "ns1", "pod-c", "10.0.0.3", "fd00::3")
		runSandboxes(t, resolver, sandboxA, sandboxC)

		stopSandbox(t, resolver, sandboxA)
		stopSandbox(t, resolver, sandboxA)
		removeSandbox(t, resolver, sandboxA)
		removeSandbox(t, resolver, idOnly(sandboxA))

		assertOwner(t, resolver, "10.0.0.1", "")
		assertOwner(t, resolver, "fd00::1", "")
		assertOwner(t, resolver, "10.0.0.3", "sandbox-c")
		assertOwner(t, resolver, "fd00::3", "sandbox-c")
	})
}

// The runtime snapshot includes stopped sandboxes, and containerd 2.1+ still
// reports the IPs they had, so only a sandbox whose network namespace exists
// and can be opened owns its IPs.

func TestNRIResolver_SynchronizeNetworkNamespace(t *testing.T) {
	dir := t.TempDir()
	// A socket exists but can not be opened.
	socket := filepath.Join(dir, "socket")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("Listen() failed: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	tests := []struct {
		name  string
		linux *nriapi.LinuxPodSandbox
		want  string
	}{
		{
			// containerd stops reporting the network namespace once it is torn down.
			name:  "stopped sandbox without network namespace",
			linux: &nriapi.LinuxPodSandbox{Namespaces: []*nriapi.LinuxNamespace{{Type: "pid"}}},
			want:  "",
		},
		{
			name:  "runtime does not report the namespaces",
			linux: nil,
			want:  "",
		},
		{
			name:  "network namespace does not exist",
			linux: networkNamespace(filepath.Join(dir, "missing")),
			want:  "",
		},
		{
			name:  "network namespace can not be opened",
			linux: networkNamespace(socket),
			want:  "",
		},
		{
			name:  "network namespace exists",
			linux: networkNamespace(liveNetNS),
			want:  "sandbox-a",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := newTestResolver()
			sandbox := makeSandbox("sandbox-a", "uid-a", "ns1", "pod-a", "10.0.0.1", "fd00::1")
			sandbox.Linux = tt.linux

			synchronize(t, resolver, sandbox)

			assertOwner(t, resolver, "10.0.0.1", tt.want)
			assertOwner(t, resolver, "fd00::1", tt.want)
		})
	}
}

func TestNRIResolver_RunPodSandboxWithoutNetworkNamespace(t *testing.T) {
	// RunPodSandbox is called for a sandbox that the runtime has just created,
	// its IPs are not checked against the network namespace.
	resolver := newTestResolver()
	sandbox := makeSandbox("sandbox-a", "uid-a", "ns1", "pod-a", "10.0.0.1", "fd00::1")
	sandbox.Linux = networkNamespace(filepath.Join(t.TempDir(), "missing"))

	runSandboxes(t, resolver, sandbox)

	assertOwner(t, resolver, "10.0.0.1", "sandbox-a")
	assertOwner(t, resolver, "fd00::1", "sandbox-a")
}

func TestNRIResolver_SynchronizeAfterReconnect(t *testing.T) {
	stopped := func(sandbox *nriapi.PodSandbox) *nriapi.PodSandbox {
		sandbox = makeSandbox(sandbox.Id, sandbox.Uid, sandbox.Namespace, sandbox.Name, sandbox.Ips...)
		sandbox.Linux = networkNamespace(filepath.Join(t.TempDir(), sandbox.Id))
		return sandbox
	}
	sandboxA := makeSandbox("sandbox-a", "uid-a", "ns1", "pod-a", "10.0.0.1", "fd00::1")
	sandboxB := makeSandbox("sandbox-b", "uid-b", "ns1", "pod-b", "10.0.0.1", "fd00::1")

	t.Run("stopped sandbox with its old IPs", func(t *testing.T) {
		resolver := newTestResolver()
		runSandboxes(t, resolver, sandboxA)

		// sandbox-a stopped while the plugin was disconnected.
		synchronize(t, resolver, stopped(sandboxA))

		assertOwner(t, resolver, "10.0.0.1", "")
		assertOwner(t, resolver, "fd00::1", "")
	})

	for _, order := range []string{"stopped first", "running first"} {
		t.Run("stopped sandbox and a running sandbox with the same IPs, "+order, func(t *testing.T) {
			resolver := newTestResolver()
			runSandboxes(t, resolver, sandboxA)

			// The IPs of sandbox-a were assigned to sandbox-b while the plugin
			// was disconnected, only sandbox-b claims them.
			snapshot := []*nriapi.PodSandbox{stopped(sandboxA), sandboxB}
			if order == "running first" {
				snapshot = []*nriapi.PodSandbox{sandboxB, stopped(sandboxA)}
			}
			synchronize(t, resolver, snapshot...)

			assertOwner(t, resolver, "10.0.0.1", "sandbox-b")
			assertOwner(t, resolver, "fd00::1", "sandbox-b")
		})
	}
}

// A stopped sandbox never runs again, but the runtime snapshot lists it until
// it is removed, and its network namespace may still exist, for example if
// tearing down the network failed.

func TestNRIResolver_SynchronizeStoppedSandbox(t *testing.T) {
	sandboxA := makeSandbox("sandbox-a", "uid-a", "ns1", "pod-a", "10.0.0.1", "fd00::1")
	sandboxB := makeSandbox("sandbox-b", "uid-b", "ns1", "pod-b", "10.0.0.1", "fd00::1")

	t.Run("stopped sandbox with its network namespace", func(t *testing.T) {
		resolver := newTestResolver()
		runSandboxes(t, resolver, sandboxA)
		stopSandbox(t, resolver, sandboxA)

		synchronize(t, resolver, sandboxA)

		assertOwner(t, resolver, "10.0.0.1", "")
		assertOwner(t, resolver, "fd00::1", "")
	})

	t.Run("stop event without IPs", func(t *testing.T) {
		resolver := newTestResolver()
		runSandboxes(t, resolver, sandboxA)
		stopSandbox(t, resolver, idOnly(sandboxA))

		synchronize(t, resolver, sandboxA)

		assertOwner(t, resolver, "10.0.0.1", "")
		assertOwner(t, resolver, "fd00::1", "")
	})

	t.Run("sandbox stopped before it was known", func(t *testing.T) {
		resolver := newTestResolver()
		stopSandbox(t, resolver, idOnly(sandboxA))

		synchronize(t, resolver, sandboxA)

		assertOwner(t, resolver, "10.0.0.1", "")
		assertOwner(t, resolver, "fd00::1", "")
	})

	for _, order := range []string{"stopped first", "running first"} {
		t.Run("stopped sandbox and the new owner of its IPs, "+order, func(t *testing.T) {
			resolver := newTestResolver()
			runSandboxes(t, resolver, sandboxA)
			stopSandbox(t, resolver, sandboxA)

			// sandbox-b got the IPs while the plugin was disconnected.
			snapshot := []*nriapi.PodSandbox{sandboxA, sandboxB}
			if order == "running first" {
				snapshot = []*nriapi.PodSandbox{sandboxB, sandboxA}
			}
			synchronize(t, resolver, snapshot...)

			assertOwner(t, resolver, "10.0.0.1", "sandbox-b")
			assertOwner(t, resolver, "fd00::1", "sandbox-b")
		})
	}

	t.Run("RunPodSandbox after stop", func(t *testing.T) {
		resolver := newTestResolver()
		runSandboxes(t, resolver, sandboxA)
		stopSandbox(t, resolver, sandboxA)
		synchronize(t, resolver, sandboxA)

		// RunPodSandbox is authoritative.
		runSandboxes(t, resolver, sandboxA)
		assertOwner(t, resolver, "10.0.0.1", "sandbox-a")
		assertOwner(t, resolver, "fd00::1", "sandbox-a")

		synchronize(t, resolver, sandboxA)
		assertOwner(t, resolver, "10.0.0.1", "sandbox-a")
		assertOwner(t, resolver, "fd00::1", "sandbox-a")
	})

	t.Run("synchronize before stop", func(t *testing.T) {
		resolver := newTestResolver()
		runSandboxes(t, resolver, sandboxA)
		synchronize(t, resolver, sandboxA)
		assertOwner(t, resolver, "10.0.0.1", "sandbox-a")

		stopSandbox(t, resolver, sandboxA)

		assertOwner(t, resolver, "10.0.0.1", "")
		assertOwner(t, resolver, "fd00::1", "")
	})
}

// A stopped sandbox is forgotten when it is removed, or when the runtime
// snapshot does not list it anymore, so the stopped sandboxes do not grow
// beyond the sandboxes that the runtime has.
func TestNRIResolver_StoppedSandboxesCleanup(t *testing.T) {
	sandboxA := makeSandbox("sandbox-a", "uid-a", "ns1", "pod-a", "10.0.0.1", "fd00::1")
	assertStopped := func(t *testing.T, resolver *NRIResolver, want ...string) {
		t.Helper()
		if !resolver.stopped.Equal(sets.New(want...)) {
			t.Errorf("stopped sandboxes = %v, want %v", sets.List(resolver.stopped), want)
		}
	}

	t.Run("removed sandbox", func(t *testing.T) {
		resolver := newTestResolver()
		runSandboxes(t, resolver, sandboxA)
		stopSandbox(t, resolver, sandboxA)
		assertStopped(t, resolver, "sandbox-a")

		removeSandbox(t, resolver, idOnly(sandboxA))
		assertStopped(t, resolver)
	})

	t.Run("sandbox listed by the snapshot", func(t *testing.T) {
		resolver := newTestResolver()
		runSandboxes(t, resolver, sandboxA)
		stopSandbox(t, resolver, sandboxA)

		synchronize(t, resolver, sandboxA)
		assertStopped(t, resolver, "sandbox-a")

		// The snapshot also lists a stopped sandbox without network namespace.
		torn := makeSandbox("sandbox-a", "uid-a", "ns1", "pod-a", "10.0.0.1", "fd00::1")
		torn.Linux = &nriapi.LinuxPodSandbox{Namespaces: []*nriapi.LinuxNamespace{{Type: "pid"}}}
		synchronize(t, resolver, torn)
		assertStopped(t, resolver, "sandbox-a")
	})

	t.Run("sandbox missing from the snapshot", func(t *testing.T) {
		resolver := newTestResolver()
		runSandboxes(t, resolver, sandboxA)
		stopSandbox(t, resolver, sandboxA)

		synchronize(t, resolver)
		assertStopped(t, resolver)
	})

	t.Run("RunPodSandbox", func(t *testing.T) {
		resolver := newTestResolver()
		stopSandbox(t, resolver, idOnly(sandboxA))

		runSandboxes(t, resolver, sandboxA)
		assertStopped(t, resolver)
	})
}

// A StopPodSandbox from the previous connection to the runtime can race with
// the Synchronize of the new one, the sandbox must not own its IPs whichever
// runs first.
func TestNRIResolver_StopAndSynchronizeInterleaving(t *testing.T) {
	sandboxA := makeSandbox("sandbox-a", "uid-a", "ns1", "pod-a", "10.0.0.1", "fd00::1")
	for i := range 200 {
		resolver := newTestResolver()
		runSandboxes(t, resolver, sandboxA)

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = resolver.StopPodSandbox(context.Background(), sandboxA)
		}()
		go func() {
			defer wg.Done()
			_, _ = resolver.Synchronize(context.Background(), []*nriapi.PodSandbox{sandboxA}, nil)
		}()
		wg.Wait()

		if owner := sandboxOwner(t, resolver, "10.0.0.1"); owner != "" {
			t.Fatalf("iteration %d: owner of 10.0.0.1 = %q, want none", i, owner)
		}
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
