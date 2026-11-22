/*
Copyright 2026 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package dht

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	v1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/kube-network-policies/pkg/api"
	pkgdht "sigs.k8s.io/kube-network-policies/pkg/dht"
	"sigs.k8s.io/kube-network-policies/pkg/network"
	"sigs.k8s.io/kube-network-policies/pkg/networkpolicy"
)

func TestMembersFromEndpointSlices(t *testing.T) {
	v4 := &discoveryv1.EndpointSlice{
		ObjectMeta:  metav1.ObjectMeta{Name: "dht-v4", Namespace: "kube-system"},
		AddressType: discoveryv1.AddressTypeIPv4,
		Ports:       []discoveryv1.EndpointPort{{Name: ptr.To("dht"), Port: ptr.To(int32(19091))}},
		Endpoints: []discoveryv1.Endpoint{
			{Addresses: []string{"10.0.0.1"}, NodeName: ptr.To("node-1"), Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true)}},
			{Addresses: []string{"10.0.0.2"}, NodeName: ptr.To("node-2"), Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(false)}},
			{Addresses: []string{"10.0.0.3"}, NodeName: ptr.To("node-3")},
		},
	}
	v6 := &discoveryv1.EndpointSlice{
		ObjectMeta:  metav1.ObjectMeta{Name: "dht-v6", Namespace: "kube-system"},
		AddressType: discoveryv1.AddressTypeIPv6,
		Ports:       []discoveryv1.EndpointPort{{Name: ptr.To("dht"), Port: ptr.To(int32(19091))}},
		Endpoints: []discoveryv1.Endpoint{
			{Addresses: []string{"fd00::1"}, NodeName: ptr.To("node-1"), Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true)}},
		},
	}

	gotV4 := MembersFromEndpointSlices([]*discoveryv1.EndpointSlice{v4, v6}, 19091)
	wantV4 := []pkgdht.Member{
		{NodeName: "node-1", Address: "10.0.0.1:19091"},
		{NodeName: "node-3", Address: "10.0.0.3:19091"},
	}
	if diff := cmp.Diff(wantV4, gotV4); diff != "" {
		t.Fatalf("IPv4 members mismatch (-want +got):\n%s", diff)
	}

	gotV6 := MembersFromEndpointSlices([]*discoveryv1.EndpointSlice{v6}, 19091)
	wantV6 := []pkgdht.Member{
		{NodeName: "node-1", Address: "[fd00::1]:19091"},
	}
	if diff := cmp.Diff(wantV6, gotV6); diff != "" {
		t.Fatalf("IPv6 members mismatch (-want +got):\n%s", diff)
	}
}

func TestProvider_CrossNodePolicyAndLiveNamespaceLabels(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Spin up two real HTTP/2 DHT nodes.
	startNode := func(name string) *pkgdht.DHT {
		n, err := pkgdht.New(pkgdht.Config{
			NodeName:          name,
			ListenAddress:     "127.0.0.1:0",
			ReplicationFactor: 2,
			RecordTTL:         30 * time.Second,
			CacheTTL:          150 * time.Millisecond,
			NegativeCacheTTL:  100 * time.Millisecond,
			RPCTimeout:        500 * time.Millisecond,
		})
		if err != nil {
			t.Fatalf("dht.New(%s): %v", name, err)
		}
		done := make(chan error, 1)
		go func() { done <- n.Run(ctx) }()
		t.Cleanup(func() { cancel(); <-done })
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) && n.ListenAddr() == "" {
			time.Sleep(10 * time.Millisecond)
		}
		if n.ListenAddr() == "" {
			t.Fatalf("node %s did not start listening", name)
		}
		return n
	}

	dht1 := startNode("node-1")
	dht2 := startNode("node-2")

	members := []pkgdht.Member{
		{NodeName: "node-1", Address: dht1.ListenAddr()},
		{NodeName: "node-2", Address: dht2.ListenAddr()},
	}
	dht1.UpdateMembers(members)
	dht2.UpdateMembers(members)

	// Fake Kubernetes objects: client pod on node-1, server pod on node-2.
	nsDev := &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "dev", Labels: map[string]string{"env": "dev"}}}
	nsProd := &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "prod", Labels: map[string]string{"env": "prod"}}}
	podCli := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "cli", Namespace: "dev", UID: types.UID("uid-cli"), Labels: map[string]string{"access": "allowed"}},
		Spec:       v1.PodSpec{NodeName: "node-1"},
		Status:     v1.PodStatus{Phase: v1.PodRunning, PodIPs: []v1.PodIP{{IP: "10.244.1.10"}}},
	}
	podSrv := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "prod", UID: types.UID("uid-srv"), Labels: map[string]string{"app": "web"}},
		Spec: v1.PodSpec{
			NodeName: "node-2",
			Containers: []v1.Container{{
				Name:  "web",
				Ports: []v1.ContainerPort{{Name: "http", ContainerPort: 8080, Protocol: v1.ProtocolTCP}},
			}},
		},
		Status: v1.PodStatus{Phase: v1.PodRunning, PodIPs: []v1.PodIP{{IP: "10.244.2.10"}}},
	}
	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "allow-prod-http", Namespace: "prod"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				Ports: []networkingv1.NetworkPolicyPort{{
					Protocol: ptr.To(v1.ProtocolTCP),
					Port:     ptr.To(intstr.FromString("http")),
				}},
				From: []networkingv1.NetworkPolicyPeer{{
					NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
					PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"access": "allowed"}},
				}},
			}},
		},
	}

	// Node-1 sees ONLY node-1's pod; Node-2 sees ONLY node-2's pod (true node-scoped watches!).
	cli1 := fake.NewSimpleClientset(nsDev, nsProd, podCli)
	f1 := informers.NewSharedInformerFactory(cli1, 0)
	prov1, err := NewProvider("node-1", f1.Core().V1().Pods(), f1.Core().V1().Namespaces(), nil, dht1)
	if err != nil {
		t.Fatalf("NewProvider(node-1): %v", err)
	}
	_ = prov1

	cli2 := fake.NewSimpleClientset(nsDev, nsProd, podSrv, np)
	f2 := informers.NewSharedInformerFactory(cli2, 0)
	prov2, err := NewProvider("node-2", f2.Core().V1().Pods(), f2.Core().V1().Namespaces(), nil, dht2)
	if err != nil {
		t.Fatalf("NewProvider(node-2): %v", err)
	}
	eval2 := networkpolicy.NewStandardNetworkPolicy("node-2", f2.Core().V1().Namespaces(), f2.Core().V1().Pods(), f2.Networking().V1().NetworkPolicies())
	engine2 := networkpolicy.NewPolicyEngine(prov2, []api.PolicyEvaluator{eval2})

	f1.Start(ctx.Done())
	f2.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(),
		f1.Core().V1().Pods().Informer().HasSynced,
		f1.Core().V1().Namespaces().Informer().HasSynced,
		f2.Core().V1().Pods().Informer().HasSynced,
		f2.Core().V1().Namespaces().Informer().HasSynced,
		f2.Networking().V1().NetworkPolicies().Informer().HasSynced,
	) {
		t.Fatalf("informers failed to sync")
	}

	// Wait until node-2 resolves node-1's pod via the DHT.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if info, ok := prov2.GetPodInfoByIP("10.244.1.10"); ok && info.UID == "uid-cli" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	pkt := &network.Packet{
		SrcIP:   net.ParseIP("10.244.1.10"),
		SrcPort: 45000,
		DstIP:   net.ParseIP("10.244.2.10"),
		DstPort: 8080,
		Proto:   v1.ProtocolTCP,
	}

	// Denied while dev namespace has env=dev.
	allowed, err := engine2.EvaluatePacket(ctx, pkt)
	if err != nil || allowed {
		t.Fatalf("EvaluatePacket(dev) = (%v, %v), want (false, nil)", allowed, err)
	}

	// Update Namespace label locally on node-2's apiserver -> allowed IMMEDIATELY
	// with zero DHT writes because Namespace.Labels are hydrated locally on read!
	nsDevUpdated := nsDev.DeepCopy()
	nsDevUpdated.Labels["env"] = "prod"
	if _, err := cli2.CoreV1().Namespaces().Update(ctx, nsDevUpdated, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("updating namespace label: %v", err)
	}
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		allowed, err = engine2.EvaluatePacket(ctx, pkt)
		if err == nil && allowed {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil || !allowed {
		t.Fatalf("EvaluatePacket() did not allow after live Namespace label mutation: allowed=%v err=%v", allowed, err)
	}

	// Clearing all labels on the namespace must immediately revert back to deny.
	nsDevCleared := nsDevUpdated.DeepCopy()
	nsDevCleared.Labels = nil
	if _, err := cli2.CoreV1().Namespaces().Update(ctx, nsDevCleared, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("clearing namespace labels: %v", err)
	}
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		allowed, err = engine2.EvaluatePacket(ctx, pkt)
		if err == nil && !allowed {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("EvaluatePacket() did not deny after clearing Namespace labels: allowed=%v err=%v", allowed, err)
}

func startTestDHT(t *testing.T, parentCtx context.Context, name string) *pkgdht.DHT {
	t.Helper()
	ctx, cancel := context.WithCancel(parentCtx)
	n, err := pkgdht.New(pkgdht.Config{
		NodeName:          name,
		ListenAddress:     "127.0.0.1:0",
		ReplicationFactor: 2,
		RecordTTL:         30 * time.Second,
		CacheTTL:          100 * time.Millisecond,
		NegativeCacheTTL:  50 * time.Millisecond,
		RPCTimeout:        500 * time.Millisecond,
	})
	if err != nil {
		cancel()
		t.Fatalf("dht.New(%s): %v", name, err)
	}
	done := make(chan error, 1)
	go func() { done <- n.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && n.ListenAddr() == "" {
		time.Sleep(10 * time.Millisecond)
	}
	if n.ListenAddr() == "" {
		t.Fatalf("node %s did not start listening", name)
	}
	return n
}

func TestWatchEndpointSlices_SyncsMembership(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	dht1 := startTestDHT(t, ctx, "node-1")
	dht2 := startTestDHT(t, ctx, "node-2")

	host1, port1Str, err := net.SplitHostPort(dht1.ListenAddr())
	if err != nil {
		t.Fatalf("SplitHostPort(dht1): %v", err)
	}
	port1, err := strconv.Atoi(port1Str)
	if err != nil {
		t.Fatalf("Atoi(%s): %v", port1Str, err)
	}
	host2, port2Str, err := net.SplitHostPort(dht2.ListenAddr())
	if err != nil {
		t.Fatalf("SplitHostPort(dht2): %v", err)
	}
	port2, err := strconv.Atoi(port2Str)
	if err != nil {
		t.Fatalf("Atoi(%s): %v", port2Str, err)
	}

	// Two single-endpoint EndpointSlices (different ephemeral ports on loopback).
	es1 := &discoveryv1.EndpointSlice{
		ObjectMeta:  metav1.ObjectMeta{Name: "dht-1", Namespace: "kube-system"},
		AddressType: discoveryv1.AddressTypeIPv4,
		Ports:       []discoveryv1.EndpointPort{{Name: ptr.To("dht"), Port: ptr.To(int32(port1))}},
		Endpoints: []discoveryv1.Endpoint{{
			Addresses:  []string{host1},
			NodeName:   ptr.To("node-1"),
			Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true)},
		}},
	}
	es2 := &discoveryv1.EndpointSlice{
		ObjectMeta:  metav1.ObjectMeta{Name: "dht-2", Namespace: "kube-system"},
		AddressType: discoveryv1.AddressTypeIPv4,
		Ports:       []discoveryv1.EndpointPort{{Name: ptr.To("dht"), Port: ptr.To(int32(port2))}},
		Endpoints: []discoveryv1.Endpoint{{
			Addresses:  []string{host2},
			NodeName:   ptr.To("node-2"),
			Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true)},
		}},
	}

	// Start with only es1 so we also exercise the single-EndpointSlice initial sync path.
	cli := fake.NewSimpleClientset(es1)
	factory := informers.NewSharedInformerFactory(cli, 0)
	epInformer := factory.Discovery().V1().EndpointSlices()

	synced1, err := WatchEndpointSlices(ctx, dht1, epInformer, "kube-system", 19091)
	if err != nil {
		t.Fatalf("WatchEndpointSlices(dht1): %v", err)
	}
	synced2, err := WatchEndpointSlices(ctx, dht2, epInformer, "kube-system", 19091)
	if err != nil {
		t.Fatalf("WatchEndpointSlices(dht2): %v", err)
	}

	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), synced1, synced2) {
		t.Fatalf("EndpointSlice informer did not sync")
	}

	dht1.Publish("10.244.1.77", &api.PodInfo{
		Name:      "pod-a",
		UID:       "uid-a",
		Namespace: &api.Namespace{Name: "default"},
		IPs:       []string{"10.244.1.77"},
	})

	// node-2 must discover node-1 via es1 alone and resolve the pod.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if info, ok := dht2.GetPodInfoByIP("10.244.1.77"); ok && info.UID == "uid-a" {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	info, ok := dht2.GetPodInfoByIP("10.244.1.77")
	if !ok || info.UID != "uid-a" {
		t.Fatalf("dht2 did not resolve pod published on dht1 via EndpointSlice discovery: got (%v, %v)", info, ok)
	}

	// Add es2 dynamically and verify node-1 rebalances/replicates to node-2.
	if _, err := cli.DiscoveryV1().EndpointSlices("kube-system").Create(ctx, es2, metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating es2: %v", err)
	}
	dht2.Publish("10.244.2.88", &api.PodInfo{
		Name:      "pod-b",
		UID:       "uid-b",
		Namespace: &api.Namespace{Name: "default"},
		IPs:       []string{"10.244.2.88"},
	})
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if info, ok := dht1.GetPodInfoByIP("10.244.2.88"); ok && info.UID == "uid-b" {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("dht1 did not resolve pod published on dht2 after adding es2")
}

func TestProvider_NRILifecycleAndIPReuse(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	dht1 := startTestDHT(t, ctx, "node-1")
	dht2 := startTestDHT(t, ctx, "node-2")
	members := []pkgdht.Member{
		{NodeName: "node-1", Address: dht1.ListenAddr()},
		{NodeName: "node-2", Address: dht2.ListenAddr()},
	}
	dht1.UpdateMembers(members)
	dht2.UpdateMembers(members)

	cli1 := fake.NewSimpleClientset()
	f1 := informers.NewSharedInformerFactory(cli1, 0)
	prov1, err := NewProvider("node-1", f1.Core().V1().Pods(), f1.Core().V1().Namespaces(), nil, dht1)
	if err != nil {
		t.Fatalf("NewProvider(node-1): %v", err)
	}
	f1.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), f1.Core().V1().Pods().Informer().HasSynced) {
		t.Fatalf("informer failed to sync")
	}

	waitRemote := func(ip, wantUID string) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			info, ok := dht2.GetPodInfoByIP(ip)
			if wantUID == "" && !ok {
				return
			}
			if wantUID != "" && ok && info.UID == wantUID {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		got, ok := dht2.GetPodInfoByIP(ip)
		t.Fatalf("remote lookup(%s) = (%v, %v), want UID=%q", ip, got, ok, wantUID)
	}

	// 1. NRI publishes pod-1 immediately before apiserver knows about it.
	prov1.OnNRIUpsert(&api.PodInfo{
		Name:      "pod-1",
		UID:       "uid-1",
		Namespace: &api.Namespace{Name: "default"},
		Labels:    map[string]string{"app": "v1"},
		IPs:       []string{"10.244.1.50"},
	})
	waitRemote("10.244.1.50", "uid-1")

	// 2. NRI stops pod-1 -> tombstone removes it from DHT.
	prov1.OnNRIDelete("uid-1", []string{"10.244.1.50"})
	waitRemote("10.244.1.50", "")

	// 3. Stale apiserver Pod event for uid-1 MUST be ignored (no resurrection).
	stalePod1 := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "pod-1", Namespace: "default", UID: types.UID("uid-1")},
		Spec:       v1.PodSpec{NodeName: "node-1"},
		Status:     v1.PodStatus{Phase: v1.PodRunning, PodIPs: []v1.PodIP{{IP: "10.244.1.50"}}},
	}
	if _, err := cli1.CoreV1().Pods("default").Create(ctx, stalePod1, metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating stalePod1: %v", err)
	}
	time.Sleep(150 * time.Millisecond)
	if info, ok := dht2.GetPodInfoByIP("10.244.1.50"); ok {
		t.Fatalf("stale apiserver update resurrected stopped pod: %v", info)
	}

	// 4. IP reuse: pod-2 reclaims 10.244.1.50; deleting stalePod1 must NOT wipe pod-2.
	pod2 := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "pod-2", Namespace: "default", UID: types.UID("uid-2")},
		Spec:       v1.PodSpec{NodeName: "node-1"},
		Status:     v1.PodStatus{Phase: v1.PodRunning, PodIPs: []v1.PodIP{{IP: "10.244.1.50"}}},
	}
	if _, err := cli1.CoreV1().Pods("default").Create(ctx, pod2, metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating pod2: %v", err)
	}
	waitRemote("10.244.1.50", "uid-2")

	if err := cli1.CoreV1().Pods("default").Delete(ctx, "pod-1", metav1.DeleteOptions{}); err != nil {
		t.Fatalf("deleting stalePod1: %v", err)
	}
	time.Sleep(150 * time.Millisecond)
	waitRemote("10.244.1.50", "uid-2")

	// 5. Transitioning pod-2 to PodSucceeded (!api.PodOwnsIPs) releases the IP.
	pod2Done := pod2.DeepCopy()
	pod2Done.Status.Phase = v1.PodSucceeded
	if _, err := cli1.CoreV1().Pods("default").Update(ctx, pod2Done, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("updating pod2 to Succeeded: %v", err)
	}
	waitRemote("10.244.1.50", "")
}

func TestProvider_OutagePropagatesErrorToPolicyEngine(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// Bind and immediately close a TCP port so RPCs fail deterministically with connection refused.
	deadLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	deadAddr := deadLis.Addr().String()
	_ = deadLis.Close()

	dht2 := startTestDHT(t, ctx, "node-2")
	// Put ONLY the dead peer on the ring so every remote lookup fails.
	dht2.UpdateMembers([]pkgdht.Member{{NodeName: "dead-node", Address: deadAddr}})

	nsProd := &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "prod"}}
	podSrv := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "prod", UID: types.UID("uid-srv"), Labels: map[string]string{"app": "web"}},
		Spec:       v1.PodSpec{NodeName: "node-2"},
		Status:     v1.PodStatus{Phase: v1.PodRunning, PodIPs: []v1.PodIP{{IP: "10.244.2.10"}}},
	}
	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "default-deny", Namespace: "prod"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		},
	}

	cli2 := fake.NewSimpleClientset(nsProd, podSrv, np)
	f2 := informers.NewSharedInformerFactory(cli2, 0)
	prov2, err := NewProvider("node-2", f2.Core().V1().Pods(), f2.Core().V1().Namespaces(), nil, dht2)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	eval2 := networkpolicy.NewStandardNetworkPolicy("node-2", f2.Core().V1().Namespaces(), f2.Core().V1().Pods(), f2.Networking().V1().NetworkPolicies())
	engine2 := networkpolicy.NewPolicyEngine(prov2, []api.PolicyEvaluator{eval2})

	f2.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(),
		f2.Core().V1().Pods().Informer().HasSynced,
		f2.Core().V1().Namespaces().Informer().HasSynced,
		f2.Networking().V1().NetworkPolicies().Informer().HasSynced,
	) {
		t.Fatalf("informers failed to sync")
	}

	pkt := &network.Packet{
		SrcIP:   net.ParseIP("10.244.9.9"), // remote IP -> hits dead DHT peer
		SrcPort: 45000,
		DstIP:   net.ParseIP("10.244.2.10"),
		DstPort: 80,
		Proto:   v1.ProtocolTCP,
	}
	_, evalErr := engine2.EvaluatePacket(ctx, pkt)
	if evalErr == nil {
		t.Fatalf("EvaluatePacket() returned nil error during DHT outage; want error so FailOpen/FailClosed applies")
	}
}
