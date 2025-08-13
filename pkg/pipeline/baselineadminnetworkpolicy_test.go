package pipeline

import (
	"context"
	"net"
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/kube-network-policies/pkg/api"
	"sigs.k8s.io/kube-network-policies/pkg/network"
	npav1alpha1 "sigs.k8s.io/network-policy-api/apis/v1alpha1"
	npaclientfake "sigs.k8s.io/network-policy-api/pkg/client/clientset/versioned/fake"
	npainformers "sigs.k8s.io/network-policy-api/pkg/client/informers/externalversions"
)

// makeBaselineAdminNetworkPolicyCustom is a helper to build BANP objects for tests.
func makeBaselineAdminNetworkPolicyCustom(name string, tweaks ...func(policy *npav1alpha1.BaselineAdminNetworkPolicy)) *npav1alpha1.BaselineAdminNetworkPolicy {
	policy := &npav1alpha1.BaselineAdminNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       npav1alpha1.BaselineAdminNetworkPolicySpec{},
	}
	for _, fn := range tweaks {
		fn(policy)
	}
	return policy
}

// Test_baselineAdminNetworkPolicyAction validates the BANP evaluator logic.
func Test_baselineAdminNetworkPolicyAction(t *testing.T) {
	// Test pods and namespaces
	podA := makePod("a", "foo", "192.168.1.11") // labels: {"a": "b"}
	podB := makePod("b", "bar", "192.168.2.22") // labels: {"a": "b"}
	podC := makePod("c", "baz", "192.168.3.33") // labels: {"c": "d"}

	// --- Reusable BANP Definitions ---

	// banpDenyAllIngress denies all ingress traffic to its subject.
	banpDenyAllIngress := makeBaselineAdminNetworkPolicyCustom("z-deny-all-ingress", func(p *npav1alpha1.BaselineAdminNetworkPolicy) {
		p.Spec.Subject = npav1alpha1.AdminNetworkPolicySubject{Namespaces: &metav1.LabelSelector{}}
		p.Spec.Ingress = []npav1alpha1.BaselineAdminNetworkPolicyIngressRule{{
			Action: npav1alpha1.BaselineAdminNetworkPolicyRuleActionDeny,
			From:   []npav1alpha1.AdminNetworkPolicyIngressPeer{{Namespaces: &metav1.LabelSelector{}}},
		}}
	})

	// banpDenyAllEgress denies all egress traffic from its subject.
	banpDenyAllEgress := makeBaselineAdminNetworkPolicyCustom("z-deny-all-egress", func(p *npav1alpha1.BaselineAdminNetworkPolicy) {
		p.Spec.Subject = npav1alpha1.AdminNetworkPolicySubject{Namespaces: &metav1.LabelSelector{}}
		p.Spec.Egress = []npav1alpha1.BaselineAdminNetworkPolicyEgressRule{{
			Action: npav1alpha1.BaselineAdminNetworkPolicyRuleActionDeny,
			To:     []npav1alpha1.BaselineAdminNetworkPolicyEgressPeer{{Namespaces: &metav1.LabelSelector{}}},
		}}
	})

	// banpAllowEgressToBar allows egress traffic to any pod in a namespace with label a=b (ns "bar").
	banpAllowEgressToBar := makeBaselineAdminNetworkPolicyCustom("a-allow-egress-to-bar", func(p *npav1alpha1.BaselineAdminNetworkPolicy) {
		p.Spec.Subject = npav1alpha1.AdminNetworkPolicySubject{Namespaces: &metav1.LabelSelector{}}
		p.Spec.Egress = []npav1alpha1.BaselineAdminNetworkPolicyEgressRule{{
			Action: npav1alpha1.BaselineAdminNetworkPolicyRuleActionAllow,
			To: []npav1alpha1.BaselineAdminNetworkPolicyEgressPeer{{
				Namespaces: &metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
			}},
		}}
	})

	// banpAllowIngressFromFoo allows ingress traffic from any pod in a namespace with label a=b (ns "foo").
	banpAllowIngressFromFoo := makeBaselineAdminNetworkPolicyCustom("a-allow-ingress-from-foo", func(p *npav1alpha1.BaselineAdminNetworkPolicy) {
		p.Spec.Subject = npav1alpha1.AdminNetworkPolicySubject{Namespaces: &metav1.LabelSelector{}}
		p.Spec.Ingress = []npav1alpha1.BaselineAdminNetworkPolicyIngressRule{{
			Action: npav1alpha1.BaselineAdminNetworkPolicyRuleActionAllow,
			From: []npav1alpha1.AdminNetworkPolicyIngressPeer{{
				Namespaces: &metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
			}},
		}}
	})

	// banpDenyEgressOnPort80 denies egress traffic on TCP port 80.
	banpDenyEgressOnPort80 := makeBaselineAdminNetworkPolicyCustom("deny-port-80", func(p *npav1alpha1.BaselineAdminNetworkPolicy) {
		p.Spec.Subject = npav1alpha1.AdminNetworkPolicySubject{Namespaces: &metav1.LabelSelector{}}
		p.Spec.Egress = []npav1alpha1.BaselineAdminNetworkPolicyEgressRule{{
			Action: npav1alpha1.BaselineAdminNetworkPolicyRuleActionDeny,
			To:     []npav1alpha1.BaselineAdminNetworkPolicyEgressPeer{{Namespaces: &metav1.LabelSelector{}}},
			Ports: &[]npav1alpha1.AdminNetworkPolicyPort{{
				PortNumber: &npav1alpha1.Port{
					Port:     80,
					Protocol: v1.ProtocolTCP,
				},
			}},
		}}
	})

	tests := []struct {
		name           string
		policies       []*npav1alpha1.BaselineAdminNetworkPolicy
		packet         network.Packet
		expected       Verdict
		testPods       []*v1.Pod
		testNamespaces []*v1.Namespace
	}{
		{
			name:     "no policies should result in VerdictNext",
			policies: []*npav1alpha1.BaselineAdminNetworkPolicy{},
			packet:   network.Packet{SrcIP: net.ParseIP("192.168.1.11"), DstIP: net.ParseIP("192.168.2.22")},
			expected: VerdictNext,
		},
		{
			name:     "deny-all-egress policy should deny traffic",
			policies: []*npav1alpha1.BaselineAdminNetworkPolicy{banpDenyAllEgress},
			packet:   network.Packet{SrcIP: net.ParseIP("192.168.1.11"), DstIP: net.ParseIP("192.168.2.22")},
			expected: VerdictDeny,
		},
		{
			name:     "deny-all-ingress policy should deny traffic",
			policies: []*npav1alpha1.BaselineAdminNetworkPolicy{banpDenyAllIngress},
			packet:   network.Packet{SrcIP: net.ParseIP("192.168.1.11"), DstIP: net.ParseIP("192.168.2.22")},
			expected: VerdictDeny,
		},
		{
			name:     "allow-egress rule found before deny-egress rule allows traffic",
			policies: []*npav1alpha1.BaselineAdminNetworkPolicy{banpAllowEgressToBar, banpDenyAllEgress},
			packet:   network.Packet{SrcIP: net.ParseIP("192.168.1.11"), DstIP: net.ParseIP("192.168.2.22")},
			expected: VerdictAccept, // Egress=Allow, Ingress=Allow(default) -> Accept
		},
		{
			name:     "allow-ingress rule found before deny-ingress rule allows traffic",
			policies: []*npav1alpha1.BaselineAdminNetworkPolicy{banpAllowIngressFromFoo, banpDenyAllIngress},
			packet:   network.Packet{SrcIP: net.ParseIP("192.168.1.11"), DstIP: net.ParseIP("192.168.2.22")},
			expected: VerdictAccept, // Egress=Allow(default), Ingress=Allow -> Accept
		},
		{
			name:     "traffic not matching specific ingress-allow defaults to allow",
			policies: []*npav1alpha1.BaselineAdminNetworkPolicy{banpAllowIngressFromFoo},
			packet:   network.Packet{SrcIP: net.ParseIP("192.168.3.33"), DstIP: net.ParseIP("192.168.2.22")}, // From podC in ns baz
			expected: VerdictAccept,                                                                          // Egress=Allow(default), Ingress=Allow(default because no rule matched) -> Accept
		},
		{
			name:     "egress traffic to a specific port is denied",
			policies: []*npav1alpha1.BaselineAdminNetworkPolicy{banpDenyEgressOnPort80},
			packet:   network.Packet{SrcIP: net.ParseIP("192.168.1.11"), DstIP: net.ParseIP("192.168.2.22"), DstPort: 80, Proto: v1.ProtocolTCP},
			expected: VerdictDeny,
		},
		{
			name:     "egress traffic to a different port is allowed by default",
			policies: []*npav1alpha1.BaselineAdminNetworkPolicy{banpDenyEgressOnPort80},
			packet:   network.Packet{SrcIP: net.ParseIP("192.168.1.11"), DstIP: net.ParseIP("192.168.2.22"), DstPort: 443, Proto: v1.ProtocolTCP},
			expected: VerdictAccept, // Egress=Allow(default), Ingress=Allow(default) -> Accept
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock clientset and informers
			npaClient := npaclientfake.NewSimpleClientset()
			npaInformerFactory := npainformers.NewSharedInformerFactory(npaClient, 0)
			banpInformer := npaInformerFactory.Policy().V1alpha1().BaselineAdminNetworkPolicies()
			banpStore := banpInformer.Informer().GetStore()
			for _, p := range tt.policies {
				banpStore.Add(p)
			}

			// Default test pods and namespaces if not specified by the test case
			pods := tt.testPods
			if pods == nil {
				pods = []*v1.Pod{podA, podB, podC}
			}
			namespaces := tt.testNamespaces
			if namespaces == nil {
				namespaces = []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar"), makeNamespace("baz")}
			}

			// podInfoGetter to simulate a live cluster cache
			getPodInfo := func(podIP string) (*api.PodInfo, bool) {
				for _, p := range pods {
					for _, ip := range p.Status.PodIPs {
						if ip.IP == podIP {
							for _, n := range namespaces {
								if n.Name == p.Namespace {
									return api.PodAndNamespaceAndNodeToPodInfo(p, n, makeNode("test-node"), ""), true
								}
							}
						}
					}
				}
				return nil, false
			}

			evaluator := NewBaselineAdminNetworkPolicyEvaluator(getPodInfo, banpInformer.Lister(), nil) // nsLister is unused

			verdict, err := evaluator.Evaluate(context.TODO(), &tt.packet)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if verdict != tt.expected {
				t.Errorf("got verdict %v, but expected %v", verdict, tt.expected)
			}
		})
	}
}
