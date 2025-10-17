// SPDX-License-Identifier: APACHE-2.0

package networkpolicy

import (
	"context"
	"net"
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/component-base/logs"
	"k8s.io/klog/v2"

	"sigs.k8s.io/kube-network-policies/pkg/api"
	"sigs.k8s.io/kube-network-policies/pkg/network"
	"sigs.k8s.io/kube-network-policies/pkg/networkpolicy"
	npav1alpha2 "sigs.k8s.io/network-policy-api/apis/v1alpha2"
	npaclientfake "sigs.k8s.io/network-policy-api/pkg/client/clientset/versioned/fake"
	npainformers "sigs.k8s.io/network-policy-api/pkg/client/informers/externalversions"
)

// FuncProvider is a test helper that wraps a function to satisfy the
// podinfo.Provider interface.
type FuncProvider struct {
	GetFunc func(podIP string) (*api.PodInfo, bool)
}

// GetPodInfoByIP calls the wrapped function.
func (f *FuncProvider) GetPodInfoByIP(podIP string) (*api.PodInfo, bool) {
	if f.GetFunc == nil {
		return nil, false // Default behavior if no function is provided
	}
	return f.GetFunc(podIP)
}

// FuncDomainResolver is a test helper that wraps a function to satisfy the
// DomainResolver interface.
type FuncDomainResolver struct {
	ContainsIPFunc func(domain string, ip net.IP) bool
}

// ContainsIP calls the wrapped function.
func (f *FuncDomainResolver) ContainsIP(domain string, ip net.IP) bool {
	if f.ContainsIPFunc == nil {
		return false // Default behavior if no function is provided
	}
	return f.ContainsIPFunc(domain, ip)
}

func makePod(name, ns string, ip string) *v1.Pod {
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			Labels: map[string]string{
				"a": "b",
			},
		},
		Spec: v1.PodSpec{
			NodeName: "testnode",
			Containers: []v1.Container{
				{
					Name:    "write-pod",
					Command: []string{"/bin/sh"},
					Ports: []v1.ContainerPort{{
						Name:          "http",
						ContainerPort: 80,
						Protocol:      v1.ProtocolTCP,
					}},
				},
			},
		},
		Status: v1.PodStatus{
			PodIPs: []v1.PodIP{
				{IP: ip},
			},
		},
	}

	return pod
}

func makeNamespace(name string) *v1.Namespace {
	return &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"kubernetes.io/metadata.name": name,
				"a":                           "b",
			},
		},
	}
}

func makeNode(name string) *v1.Node {
	return &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"kubernetes.io/node": name,
				"a":                  "b",
			},
		},
	}
}

// makeClusterNetworkPolicy is a helper to build CNP objects for tests.
func makeClusterNetworkPolicy(name string, tier npav1alpha2.Tier, priority int32, tweaks ...func(policy *npav1alpha2.ClusterNetworkPolicy)) *npav1alpha2.ClusterNetworkPolicy {
	policy := &npav1alpha2.ClusterNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: npav1alpha2.ClusterNetworkPolicySpec{
			Tier:     tier,
			Priority: priority,
		},
	}
	for _, fn := range tweaks {
		fn(policy)
	}
	return policy
}

// --- Main Evaluation Test Suite ---

func Test_ClusterNetworkPolicy_Evaluation(t *testing.T) {
	_, err := logs.GlogSetter("4")
	if err != nil {
		t.Fatal(err)
	}
	state := klog.CaptureState()
	t.Cleanup(state.Restore)

	// Test objects
	podA := makePod("a", "ns-foo", "192.168.1.11") // labels: {"app": "a"} in ns-foo (team=foo)
	podB := makePod("b", "ns-bar", "192.168.2.22") // labels: {"app": "b"} in ns-bar (team=bar)
	podC := makePod("c", "ns-baz", "192.168.3.33") // labels: {"app": "c"} in ns-baz (team=baz)

	nsFoo := makeNamespace("ns-foo")
	nsFoo.Labels["team"] = "foo"
	nsBar := makeNamespace("ns-bar")
	nsBar.Labels["team"] = "bar"
	nsBaz := makeNamespace("ns-baz")
	nsBaz.Labels["team"] = "baz"

	// --- Reusable CNP Definitions ---

	// Admin Tier Policies
	adminDenyAllEgress := makeClusterNetworkPolicy("admin-deny-all-egress", npav1alpha2.AdminTier, 100, func(p *npav1alpha2.ClusterNetworkPolicy) {
		p.Spec.Subject = npav1alpha2.ClusterNetworkPolicySubject{Namespaces: &metav1.LabelSelector{}}
		p.Spec.Egress = []npav1alpha2.ClusterNetworkPolicyEgressRule{{
			Action: npav1alpha2.ClusterNetworkPolicyRuleActionDeny,
			To:     []npav1alpha2.ClusterNetworkPolicyEgressPeer{{Namespaces: &metav1.LabelSelector{}}},
		}}
	})

	adminDenyAllEgressEmptyTo := makeClusterNetworkPolicy("admin-deny-all-egress-empty-to", npav1alpha2.AdminTier, 100, func(p *npav1alpha2.ClusterNetworkPolicy) {
		p.Spec.Subject = npav1alpha2.ClusterNetworkPolicySubject{Namespaces: &metav1.LabelSelector{}}
		p.Spec.Egress = []npav1alpha2.ClusterNetworkPolicyEgressRule{{
			Action: npav1alpha2.ClusterNetworkPolicyRuleActionDeny,
			To:     []npav1alpha2.ClusterNetworkPolicyEgressPeer{},
		}}
	})

	adminAllowEgressToNSBar := makeClusterNetworkPolicy("admin-allow-egress-to-ns-bar", npav1alpha2.AdminTier, 50, func(p *npav1alpha2.ClusterNetworkPolicy) {
		p.Spec.Subject = npav1alpha2.ClusterNetworkPolicySubject{Namespaces: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "ns-foo"}}}
		p.Spec.Egress = []npav1alpha2.ClusterNetworkPolicyEgressRule{{
			Action: npav1alpha2.ClusterNetworkPolicyRuleActionAccept,
			To:     []npav1alpha2.ClusterNetworkPolicyEgressPeer{{Namespaces: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "bar"}}}},
		}}
	})

	// Baseline Tier Policies
	baselineDenyAllIngress := makeClusterNetworkPolicy("baseline-deny-all-ingress", npav1alpha2.BaselineTier, 100, func(p *npav1alpha2.ClusterNetworkPolicy) {
		p.Spec.Subject = npav1alpha2.ClusterNetworkPolicySubject{Namespaces: &metav1.LabelSelector{}}
		p.Spec.Ingress = []npav1alpha2.ClusterNetworkPolicyIngressRule{{
			Action: npav1alpha2.ClusterNetworkPolicyRuleActionDeny,
			From:   []npav1alpha2.ClusterNetworkPolicyIngressPeer{{Namespaces: &metav1.LabelSelector{}}},
		}}
	})

	baselineDenyAllIngressEmptyFrom := makeClusterNetworkPolicy("baseline-deny-all-ingress-empty-from", npav1alpha2.BaselineTier, 100, func(p *npav1alpha2.ClusterNetworkPolicy) {
		p.Spec.Subject = npav1alpha2.ClusterNetworkPolicySubject{Namespaces: &metav1.LabelSelector{}}
		p.Spec.Ingress = []npav1alpha2.ClusterNetworkPolicyIngressRule{{
			Action: npav1alpha2.ClusterNetworkPolicyRuleActionDeny,
			From:   []npav1alpha2.ClusterNetworkPolicyIngressPeer{},
		}}
	})

	baselineAllowIngressFromNSFoo := makeClusterNetworkPolicy("baseline-allow-ingress-from-ns-foo", npav1alpha2.BaselineTier, 50, func(p *npav1alpha2.ClusterNetworkPolicy) {
		p.Spec.Subject = npav1alpha2.ClusterNetworkPolicySubject{Namespaces: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "bar"}}}
		p.Spec.Ingress = []npav1alpha2.ClusterNetworkPolicyIngressRule{{
			Action: npav1alpha2.ClusterNetworkPolicyRuleActionAccept,
			From:   []npav1alpha2.ClusterNetworkPolicyIngressPeer{{Namespaces: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "foo"}}}},
		}}
	})

	tests := []struct {
		name      string
		policies  []*npav1alpha2.ClusterNetworkPolicy
		packet    network.Packet
		wantAdmin api.Verdict
		wantBase  api.Verdict
	}{
		{
			name:      "Admin: Higher priority Allow Egress rule is effective",
			policies:  []*npav1alpha2.ClusterNetworkPolicy{adminDenyAllEgress, adminAllowEgressToNSBar},
			packet:    network.Packet{SrcIP: net.ParseIP("192.168.1.11"), DstIP: net.ParseIP("192.168.2.22")},
			wantAdmin: api.VerdictAccept, // Because adminAllowEgressToNSBar has higher priority (50 < 100)
			wantBase:  api.VerdictNext,
		},
		{
			name:      "Admin: Deny-all Egress policy is effective",
			policies:  []*npav1alpha2.ClusterNetworkPolicy{adminDenyAllEgress}, // This policy applies to all pods
			packet:    network.Packet{SrcIP: net.ParseIP("192.168.1.11"), DstIP: net.ParseIP("192.168.3.33")},
			wantAdmin: api.VerdictDeny,
			wantBase:  api.VerdictNext,
		},
		{
			name:      "Admin: Deny Egress with empty To rule",
			policies:  []*npav1alpha2.ClusterNetworkPolicy{adminDenyAllEgressEmptyTo},
			packet:    network.Packet{SrcIP: net.ParseIP("192.168.1.11"), DstIP: net.ParseIP("192.168.2.22")},
			wantAdmin: api.VerdictDeny,
			wantBase:  api.VerdictNext,
		},
		{
			name:      "Baseline: Allow Ingress from specific namespace",
			policies:  []*npav1alpha2.ClusterNetworkPolicy{baselineDenyAllIngress, baselineAllowIngressFromNSFoo},
			packet:    network.Packet{SrcIP: net.ParseIP("192.168.1.11"), DstIP: net.ParseIP("192.168.2.22")},
			wantAdmin: api.VerdictNext,
			wantBase:  api.VerdictAccept, // Allowed by baselineAllowIngressFromNSFoo
		},
		{
			name:      "Baseline: Deny Ingress from other namespace",
			policies:  []*npav1alpha2.ClusterNetworkPolicy{baselineDenyAllIngress, baselineAllowIngressFromNSFoo},
			packet:    network.Packet{SrcIP: net.ParseIP("192.168.3.33"), DstIP: net.ParseIP("192.168.2.22")},
			wantAdmin: api.VerdictNext,
			wantBase:  api.VerdictDeny, // Denied by baselineDenyAllIngress
		},
		{
			name:      "Baseline: Deny Ingress with empty From rule",
			policies:  []*npav1alpha2.ClusterNetworkPolicy{baselineDenyAllIngressEmptyFrom},
			packet:    network.Packet{SrcIP: net.ParseIP("192.168.1.11"), DstIP: net.ParseIP("192.168.2.22")},
			wantAdmin: api.VerdictNext,
			wantBase:  api.VerdictDeny,
		},
		{
			name:      "No policies applied",
			policies:  []*npav1alpha2.ClusterNetworkPolicy{},
			packet:    network.Packet{SrcIP: net.ParseIP("192.168.1.11"), DstIP: net.ParseIP("192.168.2.22")},
			wantAdmin: api.VerdictNext,
			wantBase:  api.VerdictNext,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			npaClient := npaclientfake.NewSimpleClientset()
			npaInformerFactory := npainformers.NewSharedInformerFactory(npaClient, 0)
			cnpInformer := npaInformerFactory.Policy().V1alpha2().ClusterNetworkPolicies()
			cnpStore := cnpInformer.Informer().GetStore()
			for _, p := range tt.policies {
				cnpStore.Add(p)
			}

			testPods := []*v1.Pod{podA, podB, podC}
			testNamespaces := []*v1.Namespace{nsFoo, nsBar, nsBaz}

			getPodInfo := func(podIP string) (*api.PodInfo, bool) {
				for _, p := range testPods {
					for _, ip := range p.Status.PodIPs {
						if ip.IP == podIP {
							for _, n := range testNamespaces {
								if n.Name == p.Namespace {
									return api.NewPodInfo(p, n.Labels, makeNode("test-node").Labels, ""), true
								}
							}
						}
					}
				}
				return nil, false
			}
			podInfoProvider := &FuncProvider{GetFunc: getPodInfo}

			// Test Admin Tier
			adminEvaluator := NewClusterNetworkPolicy(npav1alpha2.AdminTier, cnpInformer, nil)
			adminEngine := networkpolicy.NewPolicyEngine(podInfoProvider, []api.PolicyEvaluator{adminEvaluator})
			adminVerdict, err := adminEngine.EvaluatePacket(context.TODO(), &tt.packet)
			if err != nil {
				t.Errorf("Admin Tier: unexpected error: %v", err)
			}
			if adminVerdict != verdictToBool(tt.wantAdmin) {
				t.Errorf("Admin Tier: got verdict %v, but expected %v", adminVerdict, tt.wantAdmin)
			}

			// Test Baseline Tier
			baselineEvaluator := NewClusterNetworkPolicy(npav1alpha2.BaselineTier, cnpInformer, nil)
			baselineEngine := networkpolicy.NewPolicyEngine(podInfoProvider, []api.PolicyEvaluator{baselineEvaluator})
			baselineVerdict, err := baselineEngine.EvaluatePacket(context.TODO(), &tt.packet)
			if err != nil {
				t.Errorf("Baseline Tier: unexpected error: %v", err)
			}
			if baselineVerdict != verdictToBool(tt.wantBase) {
				t.Errorf("Baseline Tier: got verdict %v, but expected %v", baselineVerdict, tt.wantBase)
			}
		})
	}
}

// verdictToBool simplifies comparison for tests where the exact verdict doesn't matter, only allow/deny.
func verdictToBool(v api.Verdict) bool {
	switch v {
	case api.VerdictAccept:
		return true
	case api.VerdictDeny:
		return false
	case api.VerdictNext:
		// For tests, we can treat 'Next' as an implicit allow, as the chain stops here.
		return true
	default:
		return false
	}
}

// --- Port Evaluation Test ---
func Test_evaluateClusterNetworkPolicyProtocols(t *testing.T) {
	pod := makePod("test-pod", "test-ns", "1.2.3.4")
	pi := func(x int32) *int32 { return &x }
	ps := func(x string) *string { return &x }

	tests := []struct {
		name     string
		policy   []npav1alpha2.ClusterNetworkPolicyProtocol
		port     int
		protocol v1.Protocol
		want     bool
	}{
		{
			name:     "empty",
			policy:   []npav1alpha2.ClusterNetworkPolicyProtocol{},
			port:     80,
			protocol: v1.ProtocolTCP,
			want:     false,
		},
		{
			name: "one policy, match",
			policy: []npav1alpha2.ClusterNetworkPolicyProtocol{
				{
					Protocol: v1.ProtocolTCP,
					Port: &npav1alpha2.ClusterNetworkPolicyPort{
						Number: pi(80),
					},
				},
			},
			port:     80,
			protocol: v1.ProtocolTCP,
			want:     true,
		},
		{
			name: "one policy, no match",
			policy: []npav1alpha2.ClusterNetworkPolicyProtocol{
				{
					Protocol: v1.ProtocolTCP,
					Port: &npav1alpha2.ClusterNetworkPolicyPort{
						Number: pi(8080),
					},
				},
			},
			port:     80,
			protocol: v1.ProtocolTCP,
			want:     false,
		},
		{
			name: "multiple policies, match",
			policy: []npav1alpha2.ClusterNetworkPolicyProtocol{
				{
					Protocol: v1.ProtocolTCP,
					Port: &npav1alpha2.ClusterNetworkPolicyPort{
						Number: pi(8080),
					},
				},
				{
					Protocol: v1.ProtocolTCP,
					Port: &npav1alpha2.ClusterNetworkPolicyPort{
						Number: pi(80),
					},
				},
			},
			port:     80,
			protocol: v1.ProtocolTCP,
			want:     true,
		},
		{
			name: "multiple policies, no match",
			policy: []npav1alpha2.ClusterNetworkPolicyProtocol{
				{
					Protocol: v1.ProtocolTCP,
					Port: &npav1alpha2.ClusterNetworkPolicyPort{
						Number: pi(8080),
					},
				},
				{
					Protocol: v1.ProtocolUDP,
					Port: &npav1alpha2.ClusterNetworkPolicyPort{
						Number: pi(80),
					},
				},
			},
			port:     80,
			protocol: v1.ProtocolTCP,
			want:     false,
		},
		{
			name: "match named port",
			policy: []npav1alpha2.ClusterNetworkPolicyProtocol{
				{
					Protocol: v1.ProtocolTCP,
					Port: &npav1alpha2.ClusterNetworkPolicyPort{
						Name: ps("http"),
					},
				},
			},
			port:     80,
			protocol: v1.ProtocolTCP,
			want:     true,
		},
		{
			name: "match port range",
			policy: []npav1alpha2.ClusterNetworkPolicyProtocol{
				{
					Protocol: v1.ProtocolTCP,
					Port: &npav1alpha2.ClusterNetworkPolicyPort{
						Range: &npav1alpha2.PortRange{Start: 80, End: 90},
					},
				},
			},
			port:     85,
			protocol: v1.ProtocolTCP,
			want:     true,
		},
		{
			name: "mixed types, match",
			policy: []npav1alpha2.ClusterNetworkPolicyProtocol{
				{
					Protocol: v1.ProtocolTCP,
					Port: &npav1alpha2.ClusterNetworkPolicyPort{
						Number: pi(9090),
					},
				},
				{
					Protocol: v1.ProtocolTCP,
					Port: &npav1alpha2.ClusterNetworkPolicyPort{
						Name: ps("http"),
					},
				},
				{
					Protocol: v1.ProtocolTCP,
					Port: &npav1alpha2.ClusterNetworkPolicyPort{
						Range: &npav1alpha2.PortRange{Start: 100, End: 200},
					},
				},
			},
			port:     80,
			protocol: v1.ProtocolTCP,
			want:     true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			podInfo := api.NewPodInfo(pod, makeNamespace("foo").Labels, makeNode("testnode").Labels, "id")
			if got := evaluateClusterNetworkPolicyProtocols(tc.policy, podInfo, tc.port, tc.protocol); got != tc.want {
				t.Errorf("evaluateClusterNetworkPolicyPort() = %v, want %v", got, tc.want)
			}
		})
	}
}

func Test_evaluateProtocolPort(t *testing.T) {
	const (
		tcp v1.Protocol = v1.ProtocolTCP
		udp v1.Protocol = v1.ProtocolUDP
	)

	pod := makePod("test", "nstest", "192.168.1.1")
	podInfo := api.NewPodInfo(pod, makeNamespace("foo").Labels, makeNode("testnode").Labels, "id")

	pi := func(x int32) *int32 { return &x }
	ps := func(x string) *string { return &x }

	tests := []struct {
		name     string
		policy   npav1alpha2.ClusterNetworkPolicyProtocol
		pod      *api.PodInfo
		port     int32
		protocol v1.Protocol
		want     bool
	}{
		{
			name: "match port number",
			policy: npav1alpha2.ClusterNetworkPolicyProtocol{
				Protocol: tcp,
				Port: &npav1alpha2.ClusterNetworkPolicyPort{
					Number: pi(80),
				},
			},
			pod:      podInfo,
			port:     80,
			protocol: tcp,
			want:     true,
		},
		{
			name: "no match wrong port number",
			policy: npav1alpha2.ClusterNetworkPolicyProtocol{
				Protocol: tcp,
				Port: &npav1alpha2.ClusterNetworkPolicyPort{
					Number: pi(80),
				},
			},
			pod:      podInfo,
			port:     8080,
			protocol: tcp,
			want:     false,
		},
		{
			name: "no match wrong protocol",
			policy: npav1alpha2.ClusterNetworkPolicyProtocol{
				Protocol: tcp,
				Port: &npav1alpha2.ClusterNetworkPolicyPort{
					Number: pi(80),
				},
			},
			pod:      podInfo,
			port:     80,
			protocol: udp,
			want:     false,
		},
		{
			name: "match named port",
			policy: npav1alpha2.ClusterNetworkPolicyProtocol{
				Protocol: tcp,
				Port: &npav1alpha2.ClusterNetworkPolicyPort{
					Name: ps("http"),
				},
			},
			pod:      podInfo,
			port:     80,
			protocol: tcp,
			want:     true,
		},
		{
			name: "no match wrong named port",
			policy: npav1alpha2.ClusterNetworkPolicyProtocol{
				Protocol: tcp,
				Port: &npav1alpha2.ClusterNetworkPolicyPort{
					Name: ps("no-match"),
				},
			},
			pod:      podInfo,
			port:     80,
			protocol: tcp,
			want:     false,
		},
		{
			name: "match port range",
			policy: npav1alpha2.ClusterNetworkPolicyProtocol{
				Protocol: tcp,
				Port: &npav1alpha2.ClusterNetworkPolicyPort{
					Range: &npav1alpha2.PortRange{Start: 80, End: 90},
				},
			},
			pod:      podInfo,
			port:     85,
			protocol: tcp,
			want:     true,
		},
		{
			name: "match port range start",
			policy: npav1alpha2.ClusterNetworkPolicyProtocol{
				Protocol: tcp,
				Port: &npav1alpha2.ClusterNetworkPolicyPort{
					Range: &npav1alpha2.PortRange{Start: 80, End: 90},
				},
			},
			pod:      podInfo,
			port:     80,
			protocol: tcp,
			want:     true,
		},
		{
			name: "match port range end",
			policy: npav1alpha2.ClusterNetworkPolicyProtocol{
				Protocol: tcp,
				Port: &npav1alpha2.ClusterNetworkPolicyPort{
					Range: &npav1alpha2.PortRange{Start: 80, End: 90},
				},
			},
			pod:      podInfo,
			port:     90,
			protocol: tcp,
			want:     true,
		},
		{
			name: "no match port range below",
			policy: npav1alpha2.ClusterNetworkPolicyProtocol{
				Protocol: tcp,
				Port: &npav1alpha2.ClusterNetworkPolicyPort{
					Range: &npav1alpha2.PortRange{Start: 80, End: 90},
				},
			},
			pod:      podInfo,
			port:     79,
			protocol: tcp,
			want:     false,
		},
		{
			name: "no match port range above",
			policy: npav1alpha2.ClusterNetworkPolicyProtocol{
				Protocol: tcp,
				Port: &npav1alpha2.ClusterNetworkPolicyPort{
					Range: &npav1alpha2.PortRange{Start: 80, End: 90},
				},
			},
			pod:      podInfo,
			port:     91,
			protocol: tcp,
			want:     false,
		},
		{
			name: "no match port range wrong protocol",
			policy: npav1alpha2.ClusterNetworkPolicyProtocol{
				Protocol: tcp,
				Port: &npav1alpha2.ClusterNetworkPolicyPort{
					Range: &npav1alpha2.PortRange{Start: 80, End: 90},
				},
			},
			pod:      podInfo,
			port:     85,
			protocol: udp,
			want:     false,
		},
		{
			name:     "empty policy",
			policy:   npav1alpha2.ClusterNetworkPolicyProtocol{},
			pod:      podInfo,
			port:     1234,
			protocol: tcp,
			want:     false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := evaluateProtocolPort(tc.policy, tc.pod, tc.port, tc.protocol)
			if got != tc.want {
				t.Errorf("evaluateProtocolPort() = %v, want %v", got, tc.want)
			}
		})
	}
}
