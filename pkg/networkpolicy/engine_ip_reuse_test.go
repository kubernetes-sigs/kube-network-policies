// SPDX-License-Identifier: APACHE-2.0

package networkpolicy

import (
	"context"
	"fmt"
	"net"
	"slices"
	"testing"

	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"sigs.k8s.io/kube-network-policies/pkg/api"
	"sigs.k8s.io/kube-network-policies/pkg/network"
	"sigs.k8s.io/kube-network-policies/pkg/podinfo"
)

// These tests evaluate packets of a new Pod that reuses the IP of a previous
// Pod with the real informer provider and the real StandardNetworkPolicy
// evaluator. NRI is faked: it reports the Pod that owns each IP of the node,
// like the NRI resolver does for the sandboxes created by the runtime.
//
// They only cover the policy engine. Whether the packets of a new Pod reach
// the policy engine depends on the dataplane rules, see ManagedIPs.

// fakeNRI reports the Pod that owns each IP of the node.
type fakeNRI map[string]podinfo.PodIdentity

func (r fakeNRI) LookupPod(ip string) (podinfo.PodIdentity, bool) {
	identity, ok := r[ip]
	return identity, ok
}

// resolverOrder is how the provider combines the fake NRI and the informer.
type resolverOrder string

const (
	// nriFirst is the order of the binaries.
	nriFirst resolverOrder = "NRI first"
	// informerFirst was the order of the binaries before NRI was preferred.
	informerFirst resolverOrder = "informer first"
	nriDisabled   resolverOrder = "NRI disabled"
)

var resolverOrders = []resolverOrder{nriFirst, informerFirst, nriDisabled}

const (
	accept = "ACCEPT"
	deny   = "DENY"
)

// reuseIPs are the IPs of a family. The reused IP belongs to the old and the
// new Pod, the client and the server are other Pods, and the external IPs are
// inside and outside of the allowed CIDR.
type reuseIPs struct {
	reused, client, server          string
	allowedCIDR                     string
	allowedExternal, deniedExternal string
}

var reuseFamilies = []struct {
	name string
	ips  reuseIPs
}{
	{"IPv4", reuseIPs{
		reused: "10.244.1.5", client: "10.244.1.6", server: "10.244.2.9",
		allowedCIDR: "198.51.100.0/24", allowedExternal: "198.51.100.7", deniedExternal: "203.0.113.7",
	}},
	{"IPv6", reuseIPs{
		reused: "fd00:10:244:1::5", client: "fd00:10:244:1::6", server: "fd00:10:244:2::9",
		allowedCIDR: "2001:db8::/64", allowedExternal: "2001:db8::7", deniedExternal: "2001:db8:1::7",
	}},
}

var (
	labelsA       = map[string]string{"app": "a"}
	labelsB       = map[string]string{"app": "b"}
	labelsClient  = map[string]string{"app": "client"}
	labelsServer  = map[string]string{"app": "server"}
	reuseNSLabels = map[string]string{"kubernetes.io/metadata.name": "ns1"}
)

// reusePod returns a Pod of ns1 on the node.
func reusePod(name, uid string, labels map[string]string, phase v1.PodPhase, ips ...string) *v1.Pod {
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: name, UID: types.UID(uid), Labels: labels},
		Spec:       v1.PodSpec{NodeName: "node1"},
		Status:     v1.PodStatus{Phase: phase},
	}
	for _, ip := range ips {
		pod.Status.PodIPs = append(pod.Status.PodIPs, v1.PodIP{IP: ip})
	}
	if len(ips) > 0 {
		pod.Status.PodIP = ips[0]
	}
	return pod
}

// terminating marks the Pod as being deleted, it still shows Running with
// its IPs until it is removed.
func terminating(pod *v1.Pod) *v1.Pod {
	now := metav1.Now()
	pod.DeletionTimestamp = &now
	return pod
}

// onRemoteNode moves the Pod to another node, so NRI does not know it.
func onRemoteNode(pod *v1.Pod) *v1.Pod {
	pod.Spec.NodeName = "node2"
	return pod
}

// nriOwner is what NRI reports for the sandbox of a Pod: its identity and the
// PodInfo built from the sandbox, the Pod may not be in the informer yet.
func nriOwner(name, uid string, labels map[string]string) podinfo.PodIdentity {
	return podinfo.PodIdentity{
		Namespace: "ns1",
		Name:      name,
		UID:       types.UID(uid),
		SandboxID: "sandbox-" + name + "-" + uid,
		PodInfo: &api.PodInfo{
			Name:      name,
			Uid:       uid,
			Labels:    labels,
			Namespace: &api.Namespace{Name: "ns1", Labels: reuseNSLabels},
			Node:      &api.Node{Name: "node1"},
		},
	}
}

// denyEgress isolates the egress of the Pods with the labels.
func denyEgress(selector map[string]string) *networkingv1.NetworkPolicy {
	return makeNP("deny-egress", "ns1", selector, []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}, nil, nil)
}

// allowClientEgressTo only allows the egress of the client Pods to the peers.
func allowClientEgressTo(peers ...networkingv1.NetworkPolicyPeer) *networkingv1.NetworkPolicy {
	return makeNP("allow-client-egress", "ns1", labelsClient, []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
		[]networkingv1.NetworkPolicyEgressRule{{To: peers}}, nil)
}

func podPeer(labels map[string]string) networkingv1.NetworkPolicyPeer {
	return networkingv1.NetworkPolicyPeer{PodSelector: &metav1.LabelSelector{MatchLabels: labels}}
}

func cidrPeer(cidr string) networkingv1.NetworkPolicyPeer {
	return networkingv1.NetworkPolicyPeer{IPBlock: &networkingv1.IPBlock{CIDR: cidr}}
}

// reuseState is the state of the cluster and of the node, and the packet.
type reuseState struct {
	pods     []*v1.Pod
	nri      fakeNRI
	policies []*networkingv1.NetworkPolicy
	src, dst string
}

// newReuseEngine returns a policy engine with the real informer provider and
// the real StandardNetworkPolicy evaluator. The objects are added to the
// informer stores in the order of the state.
func newReuseEngine(t *testing.T, order resolverOrder, state reuseState) (*PolicyEngine, api.PodInfoProvider) {
	t.Helper()
	factory := informers.NewSharedInformerFactory(fake.NewSimpleClientset(), 0)
	podInformer := factory.Core().V1().Pods()
	nsInformer := factory.Core().V1().Namespaces()
	netpolInformer := factory.Networking().V1().NetworkPolicies()

	informerResolver, err := podinfo.NewInformerResolver(podInformer.Informer())
	if err != nil {
		t.Fatalf("NewInformerResolver() failed: %v", err)
	}
	evaluator := NewStandardNetworkPolicy("node1", nsInformer, podInformer, netpolInformer)

	if err := nsInformer.Informer().GetIndexer().Add(makeTestNamespace("ns1", reuseNSLabels)); err != nil {
		t.Fatalf("adding the namespace failed: %v", err)
	}
	for _, pod := range state.pods {
		if err := podInformer.Informer().GetIndexer().Add(pod); err != nil {
			t.Fatalf("adding Pod %s failed: %v", pod.Name, err)
		}
	}
	for _, policy := range state.policies {
		if err := netpolInformer.Informer().GetIndexer().Add(policy); err != nil {
			t.Fatalf("adding NetworkPolicy %s failed: %v", policy.Name, err)
		}
	}

	var resolvers []podinfo.IPResolver
	switch order {
	case nriFirst:
		resolvers = []podinfo.IPResolver{state.nri, informerResolver}
	case informerFirst:
		resolvers = []podinfo.IPResolver{informerResolver, state.nri}
	case nriDisabled:
		resolvers = []podinfo.IPResolver{informerResolver}
	}
	provider := podinfo.NewInformerProvider(podInformer, nsInformer, nil, resolvers)
	return NewPolicyEngine(provider, []api.PolicyEvaluator{evaluator}), provider
}

func evaluateTCP(t *testing.T, engine *PolicyEngine, src, dst string) string {
	t.Helper()
	family := v1.IPv4Protocol
	if net.ParseIP(src).To4() == nil {
		family = v1.IPv6Protocol
	}
	packet := &network.Packet{Family: family, SrcIP: net.ParseIP(src), DstIP: net.ParseIP(dst), Proto: v1.ProtocolTCP, SrcPort: 40000, DstPort: 8080}
	allow, err := engine.EvaluatePacket(context.Background(), packet)
	if err != nil {
		t.Fatalf("EvaluatePacket() failed: %v", err)
	}
	if allow {
		return accept
	}
	return deny
}

// resolvedPod returns "namespace/name uid=UID" of the Pod that the IP resolves to.
func resolvedPod(provider api.PodInfoProvider, ip string) string {
	podInfo, ok := provider.GetPodInfoByIP(ip)
	if !ok || podInfo == nil {
		return "unresolved"
	}
	return fmt.Sprintf("%s/%s uid=%s", podInfo.GetNamespace().GetName(), podInfo.GetName(), podInfo.GetUid())
}

type reuseTest struct {
	name  string
	state func(ips reuseIPs) reuseState
	// owner is the Pod that the reused IP resolves to with NRI first.
	owner string
	want  map[resolverOrder]string
}

// runReuseTests evaluates the packet of each test with each resolver order,
// with the objects added in order and in reverse order. The packet is always
// accepted without the NetworkPolicies, so the verdicts come from them.
func runReuseTests(t *testing.T, tests []reuseTest) {
	t.Helper()
	for _, tt := range tests {
		for _, family := range reuseFamilies {
			t.Run(tt.name+"/"+family.name, func(t *testing.T) {
				for _, order := range resolverOrders {
					for _, reversed := range []bool{false, true} {
						state := tt.state(family.ips)
						if reversed {
							slices.Reverse(state.pods)
							slices.Reverse(state.policies)
						}
						engine, provider := newReuseEngine(t, order, state)

						got := evaluateTCP(t, engine, state.src, state.dst)

						src, dst := resolvedPod(provider, state.src), resolvedPod(provider, state.dst)
						if got != tt.want[order] {
							t.Errorf("%s, reversed=%v: %s (%s) -> %s (%s) = %s, want %s", order, reversed, state.src, src, state.dst, dst, got, tt.want[order])
						} else if !reversed {
							t.Logf("%s: %s -> %s = %s", order, src, dst, got)
						}
						if owner := resolvedPod(provider, family.ips.reused); order == nriFirst && tt.owner != "" && owner != tt.owner {
							t.Errorf("%s, reversed=%v: %s resolves to %s, want %s", order, reversed, family.ips.reused, owner, tt.owner)
						}

						state = tt.state(family.ips)
						state.policies = nil
						engine, _ = newReuseEngine(t, order, state)
						if got := evaluateTCP(t, engine, state.src, state.dst); got != accept {
							t.Errorf("%s without NetworkPolicies = %s, want %s", order, got, accept)
						}
					}
				}
			})
		}
	}
}

// A new Pod B gets the IP of a Pod A and its egress is denied. B is Pending
// and has not reported its IP, so only NRI knows that B owns the IP.
func TestPolicyEngine_IPReuse_DenyEgress(t *testing.T) {
	var tests []reuseTest
	for _, phase := range []v1.PodPhase{v1.PodSucceeded, v1.PodFailed} {
		tests = append(tests, reuseTest{
			name: "finished Pod A " + string(phase),
			state: func(ips reuseIPs) reuseState {
				return reuseState{
					pods: []*v1.Pod{
						reusePod("pod-a", "uid-a", labelsA, phase, ips.reused),
						reusePod("pod-b", "uid-b", labelsB, v1.PodPending),
						onRemoteNode(reusePod("server", "uid-server", labelsServer, v1.PodRunning, ips.server)),
					},
					nri:      fakeNRI{ips.reused: nriOwner("pod-b", "uid-b", labelsB)},
					policies: []*networkingv1.NetworkPolicy{denyEgress(labelsB)},
					src:      ips.reused,
					dst:      ips.server,
				}
			},
			owner: "ns1/pod-b uid=uid-b",
			// The informer does not resolve the IP: A is finished and B has
			// not reported its IP.
			want: map[resolverOrder]string{nriFirst: deny, informerFirst: deny, nriDisabled: accept},
		})
	}
	tests = append(tests, reuseTest{
		name: "terminating Running Pod A",
		state: func(ips reuseIPs) reuseState {
			return reuseState{
				pods: []*v1.Pod{
					terminating(reusePod("pod-a", "uid-a", labelsA, v1.PodRunning, ips.reused)),
					reusePod("pod-b", "uid-b", labelsB, v1.PodPending),
					onRemoteNode(reusePod("server", "uid-server", labelsServer, v1.PodRunning, ips.server)),
				},
				nri:      fakeNRI{ips.reused: nriOwner("pod-b", "uid-b", labelsB)},
				policies: []*networkingv1.NetworkPolicy{denyEgress(labelsB)},
				src:      ips.reused,
				dst:      ips.server,
			}
		},
		owner: "ns1/pod-b uid=uid-b",
		// The informer resolves the IP to A, that is not selected.
		want: map[resolverOrder]string{nriFirst: deny, informerFirst: accept, nriDisabled: accept},
	})
	runReuseTests(t, tests)
}

// NRI knows the new Pod B before the informer does. Its PodInfo has the labels
// of B, so the NetworkPolicy selects it.
func TestPolicyEngine_IPReuse_PodNotInInformer(t *testing.T) {
	podA := map[string]func(ip string) *v1.Pod{
		"finished Pod A": func(ip string) *v1.Pod {
			return reusePod("pod-a", "uid-a", labelsA, v1.PodSucceeded, ip)
		},
		"terminating Running Pod A": func(ip string) *v1.Pod {
			return terminating(reusePod("pod-a", "uid-a", labelsA, v1.PodRunning, ip))
		},
	}
	want := map[string]map[resolverOrder]string{
		"finished Pod A":            {nriFirst: deny, informerFirst: deny, nriDisabled: accept},
		"terminating Running Pod A": {nriFirst: deny, informerFirst: accept, nriDisabled: accept},
	}
	var tests []reuseTest
	for _, name := range []string{"finished Pod A", "terminating Running Pod A"} {
		tests = append(tests, reuseTest{
			name: name,
			state: func(ips reuseIPs) reuseState {
				return reuseState{
					pods: []*v1.Pod{
						podA[name](ips.reused),
						onRemoteNode(reusePod("server", "uid-server", labelsServer, v1.PodRunning, ips.server)),
					},
					nri:      fakeNRI{ips.reused: nriOwner("pod-b", "uid-b", labelsB)},
					policies: []*networkingv1.NetworkPolicy{denyEgress(labelsB)},
					src:      ips.reused,
					dst:      ips.server,
				}
			},
			owner: "ns1/pod-b uid=uid-b",
			want:  want[name],
		})
	}
	runReuseTests(t, tests)
}

// A StatefulSet Pod is recreated with the same name and another UID. The
// informer still has the old Pod, with other labels than the new one.
func TestPolicyEngine_IPReuse_SameNameRecreated(t *testing.T) {
	oldLabels := map[string]string{"app": "web", "revision": "1"}
	newLabels := map[string]string{"app": "web", "revision": "2"}
	tests := []reuseTest{
		{
			name: "terminating old Pod",
			state: func(ips reuseIPs) reuseState {
				return reuseState{
					pods: []*v1.Pod{
						terminating(reusePod("web-0", "uid-a", oldLabels, v1.PodRunning, ips.reused)),
						onRemoteNode(reusePod("server", "uid-server", labelsServer, v1.PodRunning, ips.server)),
					},
					nri:      fakeNRI{ips.reused: nriOwner("web-0", "uid-b", newLabels)},
					policies: []*networkingv1.NetworkPolicy{denyEgress(map[string]string{"revision": "2"})},
					src:      ips.reused,
					dst:      ips.server,
				}
			},
			owner: "ns1/web-0 uid=uid-b",
			// The informer resolves the IP to the old Pod, with the old labels.
			want: map[resolverOrder]string{nriFirst: deny, informerFirst: accept, nriDisabled: accept},
		},
		{
			name: "failed old Pod",
			state: func(ips reuseIPs) reuseState {
				return reuseState{
					pods: []*v1.Pod{
						reusePod("web-0", "uid-a", oldLabels, v1.PodFailed, ips.reused),
						onRemoteNode(reusePod("server", "uid-server", labelsServer, v1.PodRunning, ips.server)),
					},
					nri:      fakeNRI{ips.reused: nriOwner("web-0", "uid-b", newLabels)},
					policies: []*networkingv1.NetworkPolicy{denyEgress(map[string]string{"revision": "2"})},
					src:      ips.reused,
					dst:      ips.server,
				}
			},
			owner: "ns1/web-0 uid=uid-b",
			want:  map[resolverOrder]string{nriFirst: deny, informerFirst: deny, nriDisabled: accept},
		},
	}
	runReuseTests(t, tests)
}

// The client C may only connect to the Pods with the labels of B. The
// destination IP belonged to A, that does not have them.
func TestPolicyEngine_IPReuse_NewPodAsPeer(t *testing.T) {
	podA := map[string]func(ip string) *v1.Pod{
		"finished": func(ip string) *v1.Pod {
			return reusePod("pod-a", "uid-a", labelsA, v1.PodSucceeded, ip)
		},
		"terminating": func(ip string) *v1.Pod {
			return terminating(reusePod("pod-a", "uid-a", labelsA, v1.PodRunning, ip))
		},
	}
	tests := []struct {
		name      string
		podA      string
		bInformer bool
		want      map[resolverOrder]string
	}{
		// Without NRI, the IP resolves to A or to no Pod, and neither matches
		// the peer selector.
		{"terminating Pod A and pending Pod B", "terminating", true, map[resolverOrder]string{nriFirst: accept, informerFirst: deny, nriDisabled: deny}},
		{"finished Pod A and pending Pod B", "finished", true, map[resolverOrder]string{nriFirst: accept, informerFirst: accept, nriDisabled: deny}},
		{"terminating Pod A and Pod B not in the informer", "terminating", false, map[resolverOrder]string{nriFirst: accept, informerFirst: deny, nriDisabled: deny}},
		{"finished Pod A and Pod B not in the informer", "finished", false, map[resolverOrder]string{nriFirst: accept, informerFirst: accept, nriDisabled: deny}},
	}
	var reuseTests []reuseTest
	for _, tt := range tests {
		reuseTests = append(reuseTests, reuseTest{
			name: tt.name,
			state: func(ips reuseIPs) reuseState {
				pods := []*v1.Pod{
					reusePod("client", "uid-client", labelsClient, v1.PodRunning, ips.client),
					podA[tt.podA](ips.reused),
				}
				if tt.bInformer {
					pods = append(pods, reusePod("pod-b", "uid-b", labelsB, v1.PodPending))
				}
				return reuseState{
					pods: pods,
					nri: fakeNRI{
						ips.client: nriOwner("client", "uid-client", labelsClient),
						ips.reused: nriOwner("pod-b", "uid-b", labelsB),
					},
					policies: []*networkingv1.NetworkPolicy{allowClientEgressTo(podPeer(labelsB))},
					src:      ips.client,
					dst:      ips.reused,
				}
			},
			owner: "ns1/pod-b uid=uid-b",
			want:  tt.want,
		})
	}
	runReuseTests(t, reuseTests)
}

// The packets that do not involve a reused IP get the same verdicts with and
// without NRI, and a Pod with another UID, or no UID, does not authenticate
// the informer Pod with the same name.
func TestPolicyEngine_IPReuse_NormalBehavior(t *testing.T) {
	all := func(verdict string) map[resolverOrder]string {
		return map[resolverOrder]string{nriFirst: verdict, informerFirst: verdict, nriDisabled: verdict}
	}
	clientState := func(ips reuseIPs, dst string) reuseState {
		return reuseState{
			pods: []*v1.Pod{
				reusePod("client", "uid-client", labelsClient, v1.PodRunning, ips.client),
				onRemoteNode(reusePod("remote", "uid-remote", labelsB, v1.PodRunning, ips.server)),
			},
			nri:      fakeNRI{ips.client: nriOwner("client", "uid-client", labelsClient)},
			policies: []*networkingv1.NetworkPolicy{allowClientEgressTo(podPeer(labelsB), cidrPeer(ips.allowedCIDR))},
			src:      ips.client,
			dst:      dst,
		}
	}
	tests := []reuseTest{
		{
			name:  "Pod on another node",
			state: func(ips reuseIPs) reuseState { return clientState(ips, ips.server) },
			want:  all(accept),
		},
		{
			name:  "external IP in the allowed CIDR",
			state: func(ips reuseIPs) reuseState { return clientState(ips, ips.allowedExternal) },
			want:  all(accept),
		},
		{
			name:  "external IP outside of the allowed CIDR",
			state: func(ips reuseIPs) reuseState { return clientState(ips, ips.deniedExternal) },
			want:  all(deny),
		},
		{
			name: "current Pod in the informer",
			state: func(ips reuseIPs) reuseState {
				return reuseState{
					pods: []*v1.Pod{
						reusePod("pod-b", "uid-b", labelsB, v1.PodRunning, ips.reused),
						onRemoteNode(reusePod("server", "uid-server", labelsServer, v1.PodRunning, ips.server)),
					},
					nri:      fakeNRI{ips.reused: nriOwner("pod-b", "uid-b", labelsB)},
					policies: []*networkingv1.NetworkPolicy{denyEgress(labelsB)},
					src:      ips.reused,
					dst:      ips.server,
				}
			},
			owner: "ns1/pod-b uid=uid-b",
			want:  all(deny),
		},
		{
			// The informer has both Pods with the IP, B ranks first.
			name: "Pod B reported the IP of a finished Pod A",
			state: func(ips reuseIPs) reuseState {
				return reuseState{
					pods: []*v1.Pod{
						reusePod("pod-a", "uid-a", labelsA, v1.PodSucceeded, ips.reused),
						reusePod("pod-b", "uid-b", labelsB, v1.PodPending, ips.reused),
						onRemoteNode(reusePod("server", "uid-server", labelsServer, v1.PodRunning, ips.server)),
					},
					nri:      fakeNRI{ips.reused: nriOwner("pod-b", "uid-b", labelsB)},
					policies: []*networkingv1.NetworkPolicy{denyEgress(labelsB)},
					src:      ips.reused,
					dst:      ips.server,
				}
			},
			owner: "ns1/pod-b uid=uid-b",
			want:  all(deny),
		},
		{
			name: "Pod B reported the IP of a terminating Pod A",
			state: func(ips reuseIPs) reuseState {
				return reuseState{
					pods: []*v1.Pod{
						terminating(reusePod("pod-a", "uid-a", labelsA, v1.PodRunning, ips.reused)),
						reusePod("pod-b", "uid-b", labelsB, v1.PodPending, ips.reused),
						onRemoteNode(reusePod("server", "uid-server", labelsServer, v1.PodRunning, ips.server)),
					},
					nri:      fakeNRI{ips.reused: nriOwner("pod-b", "uid-b", labelsB)},
					policies: []*networkingv1.NetworkPolicy{denyEgress(labelsB)},
					src:      ips.reused,
					dst:      ips.server,
				}
			},
			owner: "ns1/pod-b uid=uid-b",
			want:  all(deny),
		},
		{
			// The informer Pod is selected, the new Pod is not.
			name: "informer Pod with the same name and another UID",
			state: func(ips reuseIPs) reuseState {
				return reuseState{
					pods: []*v1.Pod{
						terminating(reusePod("pod-b", "uid-old", labelsB, v1.PodRunning, ips.reused)),
						onRemoteNode(reusePod("server", "uid-server", labelsServer, v1.PodRunning, ips.server)),
					},
					nri:      fakeNRI{ips.reused: nriOwner("pod-b", "uid-new", map[string]string{"app": "b2"})},
					policies: []*networkingv1.NetworkPolicy{denyEgress(labelsB)},
					src:      ips.reused,
					dst:      ips.server,
				}
			},
			owner: "ns1/pod-b uid=uid-new",
			want:  map[resolverOrder]string{nriFirst: accept, informerFirst: deny, nriDisabled: deny},
		},
		{
			name: "informer Pod with the same name and NRI without UID",
			state: func(ips reuseIPs) reuseState {
				return reuseState{
					pods: []*v1.Pod{
						terminating(reusePod("pod-b", "uid-old", labelsB, v1.PodRunning, ips.reused)),
						onRemoteNode(reusePod("server", "uid-server", labelsServer, v1.PodRunning, ips.server)),
					},
					nri:      fakeNRI{ips.reused: nriOwner("pod-b", "", map[string]string{"app": "b2"})},
					policies: []*networkingv1.NetworkPolicy{denyEgress(labelsB)},
					src:      ips.reused,
					dst:      ips.server,
				}
			},
			owner: "ns1/pod-b uid=",
			want:  map[resolverOrder]string{nriFirst: accept, informerFirst: deny, nriDisabled: deny},
		},
	}
	runReuseTests(t, tests)
}
