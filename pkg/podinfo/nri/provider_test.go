//go:build linux

package nri

import (
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"sigs.k8s.io/kube-network-policies/pkg/podinfo"
)

// These tests resolve IPs with the informer provider and a real NRI resolver.
// NRI decides which Pod owns the IP of a local Pod, the informer provides the
// details of that Pod only if it has the same UID.

// newBinaryProvider returns a provider with the resolvers in the order used by
// the kube-network-policies binaries. A nil resolver means that NRI is disabled.
func newBinaryProvider(t *testing.T, resolver *NRIResolver, pods ...*v1.Pod) *podinfo.InformerProvider {
	t.Helper()
	if resolver == nil {
		return newProviderWithResolver(t, nil, pods...)
	}
	return newProviderWithResolver(t, resolver, pods...)
}

func newProviderWithResolver(t *testing.T, resolver podinfo.IPResolver, pods ...*v1.Pod) *podinfo.InformerProvider {
	t.Helper()
	informersFactory := informers.NewSharedInformerFactory(fake.NewSimpleClientset(), 0)
	podInformer := informersFactory.Core().V1().Pods()
	informerResolver, err := podinfo.NewInformerResolver(podInformer.Informer())
	if err != nil {
		t.Fatalf("NewInformerResolver() failed: %v", err)
	}
	for _, pod := range pods {
		if err := podInformer.Informer().GetIndexer().Add(pod); err != nil {
			t.Fatalf("Add() failed: %v", err)
		}
	}
	var resolvers []podinfo.IPResolver
	if resolver != nil {
		resolvers = append(resolvers, resolver)
	}
	resolvers = append(resolvers, informerResolver)
	return podinfo.NewInformerProvider(podInformer, informersFactory.Core().V1().Namespaces(), nil, resolvers)
}

// makeK8sPod returns an informer Pod, it has a container port that NRI does
// not know about.
func makeK8sPod(name, uid string, phase v1.PodPhase, nodeName string, ips ...string) *v1.Pod {
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: name, UID: types.UID(uid)},
		Spec: v1.PodSpec{
			NodeName: nodeName,
			Containers: []v1.Container{{
				Name:  "server",
				Ports: []v1.ContainerPort{{Name: "http", ContainerPort: 80, Protocol: v1.ProtocolTCP}},
			}},
		},
		Status: v1.PodStatus{Phase: phase},
	}
	for _, ip := range ips {
		pod.Status.PodIPs = append(pod.Status.PodIPs, v1.PodIP{IP: ip})
	}
	if len(ips) > 0 {
		pod.Status.PodIP = ips[0]
	}
	return pod
}

// resolvedPod returns the namespace/name of the Pod that ip resolves to and
// where its details come from, or "" if none.
func resolvedPod(provider *podinfo.InformerProvider, ip string) string {
	podInfo, ok := provider.GetPodInfoByIP(ip)
	if !ok {
		return ""
	}
	source := "informer"
	if _, ok := podInfo.Labels[sandboxIDLabel]; ok {
		source = "nri"
	}
	return podInfo.Namespace.Name + "/" + podInfo.Name + " from " + source
}

func assertResolvedPod(t *testing.T, provider *podinfo.InformerProvider, ip, want string) {
	t.Helper()
	if got := resolvedPod(provider, ip); got != want {
		t.Errorf("GetPodInfoByIP(%s) = %q, want %q", ip, got, want)
	}
}

func TestProviderWithNRI_NewPodReusesIP(t *testing.T) {
	resolver := newTestResolver()
	runSandboxes(t, resolver, makeSandbox("sandbox-b", "uid-b", "ns1", "pod-b", "10.0.0.1", "fd00::1"))
	// The informer has not observed that pod-a finished and released its IPs,
	// nor the IPs of pod-b.
	provider := newBinaryProvider(t, resolver,
		makeK8sPod("pod-a", "uid-a", v1.PodRunning, "node-1", "10.0.0.1", "fd00::1"),
		makeK8sPod("pod-b", "uid-b", v1.PodPending, "node-1"),
	)

	assertResolvedPod(t, provider, "10.0.0.1", "ns1/pod-b from informer")
	assertResolvedPod(t, provider, "fd00::1", "ns1/pod-b from informer")
}

func TestProviderWithNRI_PodNotInInformer(t *testing.T) {
	t.Run("informer has the previous pod with the IP", func(t *testing.T) {
		resolver := newTestResolver()
		runSandboxes(t, resolver, makeSandbox("sandbox-b", "uid-b", "ns1", "pod-b", "10.0.0.1", "fd00::1"))
		provider := newBinaryProvider(t, resolver,
			makeK8sPod("pod-a", "uid-a", v1.PodRunning, "node-1", "10.0.0.1", "fd00::1"),
		)

		assertResolvedPod(t, provider, "10.0.0.1", "ns1/pod-b from nri")
		assertResolvedPod(t, provider, "fd00::1", "ns1/pod-b from nri")
	})

	t.Run("informer has no pod with the IP", func(t *testing.T) {
		resolver := newTestResolver()
		runSandboxes(t, resolver, makeSandbox("sandbox-b", "uid-b", "ns1", "pod-b", "10.0.0.1", "fd00::1"))
		provider := newBinaryProvider(t, resolver)

		assertResolvedPod(t, provider, "10.0.0.1", "ns1/pod-b from nri")
		assertResolvedPod(t, provider, "fd00::1", "ns1/pod-b from nri")
	})
}

func TestProviderWithNRI_SameNameAnotherUID(t *testing.T) {
	// StatefulSets reuse the Pod names, the informer still has the previous web-0.
	for name, oldPod := range map[string]*v1.Pod{
		"old pod has the IP":     makeK8sPod("web-0", "uid-a", v1.PodRunning, "node-1", "10.0.0.1"),
		"old pod has another IP": makeK8sPod("web-0", "uid-a", v1.PodRunning, "node-1", "10.0.0.2"),
	} {
		t.Run(name, func(t *testing.T) {
			resolver := newTestResolver()
			runSandboxes(t, resolver, makeSandbox("sandbox-b", "uid-b", "ns1", "web-0", "10.0.0.1"))
			provider := newBinaryProvider(t, resolver, oldPod)

			assertResolvedPod(t, provider, "10.0.0.1", "ns1/web-0 from nri")
		})
	}
}

func TestProviderWithNRI_SameUIDWithoutIPs(t *testing.T) {
	// The informer has the Pod, with the details that NRI does not have, but
	// not its IPs yet.
	resolver := newTestResolver()
	runSandboxes(t, resolver, makeSandbox("sandbox-b", "uid-b", "ns1", "pod-b", "10.0.0.1", "fd00::1"))
	provider := newBinaryProvider(t, resolver, makeK8sPod("pod-b", "uid-b", v1.PodPending, "node-1"))

	for _, ip := range []string{"10.0.0.1", "fd00::1"} {
		podInfo, ok := provider.GetPodInfoByIP(ip)
		if !ok || podInfo.Name != "pod-b" || len(podInfo.ContainerPorts) != 1 {
			t.Errorf("GetPodInfoByIP(%s) = %v, %v; want pod-b with its container ports", ip, podInfo, ok)
		}
	}
}

func TestProviderWithNRI_OwnerWithoutUID(t *testing.T) {
	// Matching the namespace and name does not tell that it is the same Pod.
	resolver := newTestResolver()
	runSandboxes(t, resolver, makeSandbox("sandbox-b", "", "ns1", "pod-b", "10.0.0.1"))
	provider := newBinaryProvider(t, resolver, makeK8sPod("pod-b", "uid-b", v1.PodRunning, "node-1", "10.0.0.1"))

	assertResolvedPod(t, provider, "10.0.0.1", "ns1/pod-b from nri")
}

func TestProviderWithNRI_FinishedPod(t *testing.T) {
	for _, phase := range []v1.PodPhase{v1.PodSucceeded, v1.PodFailed} {
		t.Run(string(phase)+" pod with the same UID", func(t *testing.T) {
			resolver := newTestResolver()
			runSandboxes(t, resolver, makeSandbox("sandbox-a", "uid-a", "ns1", "pod-a", "10.0.0.1", "fd00::1"))
			provider := newBinaryProvider(t, resolver,
				makeK8sPod("pod-a", "uid-a", phase, "node-1", "10.0.0.1", "fd00::1"),
			)

			assertResolvedPod(t, provider, "10.0.0.1", "")
			// The API server shows that the Pod finished, its sandbox does
			// not own the IPs anymore.
			assertOwner(t, resolver, "10.0.0.1", "")
			assertOwner(t, resolver, "fd00::1", "")
		})

		t.Run(string(phase)+" pod and IP reused on another node", func(t *testing.T) {
			resolver := newTestResolver()
			runSandboxes(t, resolver, makeSandbox("sandbox-a", "uid-a", "ns1", "pod-a", "10.0.0.1"))
			provider := newBinaryProvider(t, resolver,
				makeK8sPod("pod-a", "uid-a", phase, "node-1", "10.0.0.1"),
				makeK8sPod("pod-r", "uid-r", v1.PodRunning, "node-2", "10.0.0.1"),
			)

			assertResolvedPod(t, provider, "10.0.0.1", "ns1/pod-r from informer")
			assertOwner(t, resolver, "10.0.0.1", "")
		})

		t.Run(string(phase)+" pod with another UID", func(t *testing.T) {
			// The informer still has the previous web-0, that finished.
			resolver := newTestResolver()
			runSandboxes(t, resolver, makeSandbox("sandbox-b", "uid-b", "ns1", "web-0", "10.0.0.1"))
			provider := newBinaryProvider(t, resolver, makeK8sPod("web-0", "uid-a", phase, "node-1", "10.0.0.1"))

			assertResolvedPod(t, provider, "10.0.0.1", "ns1/web-0 from nri")
			assertOwner(t, resolver, "10.0.0.1", "sandbox-b")
		})
	}

	t.Run("previous pod finished and the new owner of its IP", func(t *testing.T) {
		resolver := newTestResolver()
		runSandboxes(t, resolver,
			makeSandbox("sandbox-a", "uid-a", "ns1", "pod-a", "10.0.0.1"),
			makeSandbox("sandbox-b", "uid-b", "ns1", "pod-b", "10.0.0.1"),
		)
		provider := newBinaryProvider(t, resolver,
			makeK8sPod("pod-a", "uid-a", v1.PodSucceeded, "node-1", "10.0.0.1"),
			makeK8sPod("pod-b", "uid-b", v1.PodPending, "node-1"),
		)

		assertResolvedPod(t, provider, "10.0.0.1", "ns1/pod-b from informer")
		assertOwner(t, resolver, "10.0.0.1", "sandbox-b")
	})
}

func TestProviderWithNRI_NoOwner(t *testing.T) {
	remotePod := makeK8sPod("pod-r", "uid-r", v1.PodRunning, "node-2", "10.0.1.1", "fd00:1::1")

	t.Run("NRI disabled", func(t *testing.T) {
		provider := newBinaryProvider(t, nil, remotePod)

		assertResolvedPod(t, provider, "10.0.1.1", "ns1/pod-r from informer")
		assertResolvedPod(t, provider, "fd00:1::1", "ns1/pod-r from informer")
		assertResolvedPod(t, provider, "192.0.2.1", "")
	})

	t.Run("IP that NRI does not have", func(t *testing.T) {
		resolver := newTestResolver()
		runSandboxes(t, resolver, makeSandbox("sandbox-c", "uid-c", "ns1", "pod-c", "10.0.0.9"))
		provider := newBinaryProvider(t, resolver, remotePod)

		assertResolvedPod(t, provider, "10.0.1.1", "ns1/pod-r from informer")
		assertResolvedPod(t, provider, "fd00:1::1", "ns1/pod-r from informer")
		assertResolvedPod(t, provider, "192.0.2.1", "")
	})
}

func TestProviderWithNRI_LateStopAndRemove(t *testing.T) {
	resolver := newTestResolver()
	sandboxA := makeSandbox("sandbox-a", "uid-a", "ns1", "pod-a", "10.0.0.1", "fd00::1")
	runSandboxes(t, resolver, sandboxA, makeSandbox("sandbox-b", "uid-b", "ns1", "pod-b", "10.0.0.1", "fd00::1"))
	stopSandbox(t, resolver, sandboxA)
	removeSandbox(t, resolver, idOnly(sandboxA))
	provider := newBinaryProvider(t, resolver,
		makeK8sPod("pod-a", "uid-a", v1.PodRunning, "node-1", "10.0.0.1", "fd00::1"),
		makeK8sPod("pod-b", "uid-b", v1.PodPending, "node-1"),
	)

	assertResolvedPod(t, provider, "10.0.0.1", "ns1/pod-b from informer")
	assertResolvedPod(t, provider, "fd00::1", "ns1/pod-b from informer")
}

func TestProviderWithNRI_NamespaceLabels(t *testing.T) {
	// The PodInfo from NRI has the namespace labels when NRI has the namespace informer.
	informersFactory := informers.NewSharedInformerFactory(fake.NewSimpleClientset(), 0)
	nsInformer := informersFactory.Core().V1().Namespaces()
	namespace := &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns1", Labels: map[string]string{"team": "a"}}}
	if err := nsInformer.Informer().GetIndexer().Add(namespace); err != nil {
		t.Fatalf("Add() failed: %v", err)
	}
	resolver := newTestResolver()
	resolver.nsLister = nsInformer.Lister()
	runSandboxes(t, resolver, makeSandbox("sandbox-b", "uid-b", "ns1", "pod-b", "10.0.0.1"))
	provider := newBinaryProvider(t, resolver)

	podInfo, ok := provider.GetPodInfoByIP("10.0.0.1")
	if !ok || podInfo.Namespace.Labels["team"] != "a" {
		t.Errorf("GetPodInfoByIP() = %v, %v; want pod-b with the namespace labels", podInfo, ok)
	}
}

// racingResolver is the NRI resolver with a sandbox started right after a
// lookup, as if the runtime assigned the IP to it while the provider was still
// using the result of the lookup.
type racingResolver struct {
	*NRIResolver
	afterLookup func()
}

func (r *racingResolver) LookupPod(ip string) (podinfo.PodIdentity, bool) {
	identity, ok := r.NRIResolver.LookupPod(ip)
	if r.afterLookup != nil {
		r.afterLookup()
		r.afterLookup = nil
	}
	return identity, ok
}

func TestProviderWithNRI_FinishedPodNewSandbox(t *testing.T) {
	// The new sandbox belongs to the same Pod UID and gets the same IPs.
	resolver := newTestResolver()
	runSandboxes(t, resolver, makeSandbox("sandbox-1", "uid-a", "ns1", "pod-a", "10.0.0.1", "fd00::1"))
	racing := &racingResolver{
		NRIResolver: resolver,
		afterLookup: func() {
			runSandboxes(t, resolver, makeSandbox("sandbox-2", "uid-a", "ns1", "pod-a", "10.0.0.1", "fd00::1"))
		},
	}
	provider := newProviderWithResolver(t, racing, makeK8sPod("pod-a", "uid-a", v1.PodSucceeded, "node-1", "10.0.0.1", "fd00::1"))

	provider.GetPodInfoByIP("10.0.0.1")

	// The lookup found sandbox-1, releasing it must not release sandbox-2.
	assertOwner(t, resolver, "10.0.0.1", "sandbox-2")
	assertOwner(t, resolver, "fd00::1", "sandbox-2")
}
