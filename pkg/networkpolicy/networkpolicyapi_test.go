package networkpolicy

import (
	"context"
	"net"
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/component-base/logs"
	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"
	npav1alpha1 "sigs.k8s.io/network-policy-api/apis/v1alpha1"
)

type adminNetpolTweak func(networkPolicy *npav1alpha1.AdminNetworkPolicy)

func makeAdminNetworkPolicyCustom(name, ns string, tweaks ...adminNetpolTweak) *npav1alpha1.AdminNetworkPolicy {
	networkAdminPolicy := &npav1alpha1.AdminNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec:       npav1alpha1.AdminNetworkPolicySpec{},
	}
	for _, fn := range tweaks {
		fn(networkAdminPolicy)
	}
	return networkAdminPolicy
}

func Test_adminNetworkPolicyAction(t *testing.T) {
	_, err := logs.GlogSetter("4")
	if err != nil {
		t.Fatal(err)
	}
	state := klog.CaptureState()
	t.Cleanup(state.Restore)

	podA := makePod("a", "foo", "192.168.1.11")
	podB := makePod("b", "bar", "192.168.2.22")
	// podC will not match neither selectors or namespaces
	podC := makePod("c", "blocked", "192.168.3.33")
	podC.Labels = map[string]string{"c": "d"}
	// podD is same namespace PodB with different selectors
	podD := makePod("d", "bar", "192.168.4.44")
	podD.Labels = map[string]string{"c": "d"}

	npaDefaultDenyIngress := makeAdminNetworkPolicyCustom("default-deny-ingress", "bar",
		func(networkPolicy *npav1alpha1.AdminNetworkPolicy) {
			networkPolicy.Spec.Subject = npav1alpha1.AdminNetworkPolicySubject{Namespaces: &metav1.LabelSelector{}}
			networkPolicy.Spec.Priority = 110
			networkPolicy.Spec.Ingress = []npav1alpha1.AdminNetworkPolicyIngressRule{{
				Action: npav1alpha1.AdminNetworkPolicyRuleActionDeny,
				From:   []npav1alpha1.AdminNetworkPolicyIngressPeer{{Namespaces: &metav1.LabelSelector{}}},
			}}
		})

	npaDefaultDenyEgress := makeAdminNetworkPolicyCustom("default-deny-egress", "bar",
		func(networkPolicy *npav1alpha1.AdminNetworkPolicy) {
			networkPolicy.Spec.Subject = npav1alpha1.AdminNetworkPolicySubject{Namespaces: &metav1.LabelSelector{}}
			networkPolicy.Spec.Priority = 110
			networkPolicy.Spec.Egress = []npav1alpha1.AdminNetworkPolicyEgressRule{{
				Action: npav1alpha1.AdminNetworkPolicyRuleActionDeny,
				To:     []npav1alpha1.AdminNetworkPolicyEgressPeer{{Namespaces: &metav1.LabelSelector{}}},
			}}
		})

	npaAllowAllIngress := makeAdminNetworkPolicyCustom("default-allow-ingress", "bar",
		func(networkPolicy *npav1alpha1.AdminNetworkPolicy) {
			networkPolicy.Spec.Subject = npav1alpha1.AdminNetworkPolicySubject{Namespaces: &metav1.LabelSelector{}}
			networkPolicy.Spec.Priority = 100
			networkPolicy.Spec.Ingress = []npav1alpha1.AdminNetworkPolicyIngressRule{{
				Action: npav1alpha1.AdminNetworkPolicyRuleActionAllow,
				From:   []npav1alpha1.AdminNetworkPolicyIngressPeer{{Namespaces: &metav1.LabelSelector{}}},
			}}
		})

	npaAllowAllIngressPod := makeAdminNetworkPolicyCustom("default-allow-ingress-pods", "bar",
		func(networkPolicy *npav1alpha1.AdminNetworkPolicy) {
			networkPolicy.Spec.Subject = npav1alpha1.AdminNetworkPolicySubject{Namespaces: &metav1.LabelSelector{}}
			networkPolicy.Spec.Priority = 110
			networkPolicy.Spec.Ingress = []npav1alpha1.AdminNetworkPolicyIngressRule{{
				Action: npav1alpha1.AdminNetworkPolicyRuleActionAllow,
				From: []npav1alpha1.AdminNetworkPolicyIngressPeer{{
					Pods: &npav1alpha1.NamespacedPod{
						PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
					},
				}},
			}}
		})

	npaAllowMultiPortEgress := makeAdminNetworkPolicyCustom("multiport-egress", "foo",
		func(networkPolicy *npav1alpha1.AdminNetworkPolicy) {
			networkPolicy.Spec.Subject = npav1alpha1.AdminNetworkPolicySubject{Namespaces: &metav1.LabelSelector{}}
			networkPolicy.Spec.Priority = 10
			networkPolicy.Spec.Egress = []npav1alpha1.AdminNetworkPolicyEgressRule{{
				Action: npav1alpha1.AdminNetworkPolicyRuleActionAllow,
				To:     []npav1alpha1.AdminNetworkPolicyEgressPeer{{Namespaces: &metav1.LabelSelector{}}},
				Ports: &[]npav1alpha1.AdminNetworkPolicyPort{{
					PortRange: &npav1alpha1.PortRange{
						Protocol: v1.ProtocolTCP,
						Start:    80,
						End:      120,
					}}},
			}}
		})

	npaAllowMultiPortEgressNode := makeAdminNetworkPolicyCustom("multiport-egress", "foo",
		func(networkPolicy *npav1alpha1.AdminNetworkPolicy) {
			networkPolicy.Spec.Subject = npav1alpha1.AdminNetworkPolicySubject{Namespaces: &metav1.LabelSelector{}}
			networkPolicy.Spec.Priority = 10
			networkPolicy.Spec.Egress = []npav1alpha1.AdminNetworkPolicyEgressRule{{
				Action: npav1alpha1.AdminNetworkPolicyRuleActionAllow,
				To:     []npav1alpha1.AdminNetworkPolicyEgressPeer{{Nodes: &metav1.LabelSelector{}}},
				Ports: &[]npav1alpha1.AdminNetworkPolicyPort{{
					PortRange: &npav1alpha1.PortRange{
						Protocol: v1.ProtocolTCP,
						Start:    80,
						End:      120,
					}}},
			}}
		})

	npaAllowMultiPortEgressCIDR := makeAdminNetworkPolicyCustom("multiport-egress", "foo",
		func(networkPolicy *npav1alpha1.AdminNetworkPolicy) {
			networkPolicy.Spec.Subject = npav1alpha1.AdminNetworkPolicySubject{Namespaces: &metav1.LabelSelector{}}
			networkPolicy.Spec.Priority = 10
			networkPolicy.Spec.Egress = []npav1alpha1.AdminNetworkPolicyEgressRule{{
				Action: npav1alpha1.AdminNetworkPolicyRuleActionAllow,
				To: []npav1alpha1.AdminNetworkPolicyEgressPeer{{
					Networks: []npav1alpha1.CIDR{"192.168.0.0/16"},
				}},
				Ports: &[]npav1alpha1.AdminNetworkPolicyPort{{
					PortRange: &npav1alpha1.PortRange{
						Protocol: v1.ProtocolTCP,
						Start:    80,
						End:      120,
					}}},
			}}
		})

	npaAllowMultiPortEgressPodSelector := makeAdminNetworkPolicyCustom("multiport-egress", "foo",
		func(networkPolicy *npav1alpha1.AdminNetworkPolicy) {
			networkPolicy.Spec.Subject = npav1alpha1.AdminNetworkPolicySubject{Namespaces: &metav1.LabelSelector{}}
			networkPolicy.Spec.Priority = 100
			networkPolicy.Spec.Egress = []npav1alpha1.AdminNetworkPolicyEgressRule{{
				Action: npav1alpha1.AdminNetworkPolicyRuleActionAllow,
				To: []npav1alpha1.AdminNetworkPolicyEgressPeer{{
					Pods: &npav1alpha1.NamespacedPod{
						PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
					},
				}},
				Ports: &[]npav1alpha1.AdminNetworkPolicyPort{{
					PortRange: &npav1alpha1.PortRange{
						Protocol: v1.ProtocolTCP,
						Start:    80,
						End:      120,
					}}},
			}}
		})

	npaMultiPortEgressNsSelector := makeAdminNetworkPolicyCustom("multiport-egress-ns", "foo",
		func(networkPolicy *npav1alpha1.AdminNetworkPolicy) {
			networkPolicy.Spec.Subject = npav1alpha1.AdminNetworkPolicySubject{Namespaces: &metav1.LabelSelector{}}
			networkPolicy.Spec.Priority = 10
			networkPolicy.Spec.Egress = []npav1alpha1.AdminNetworkPolicyEgressRule{{
				Action: npav1alpha1.AdminNetworkPolicyRuleActionAllow,
				To: []npav1alpha1.AdminNetworkPolicyEgressPeer{{
					Pods: &npav1alpha1.NamespacedPod{
						NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
					},
				}},
				Ports: &[]npav1alpha1.AdminNetworkPolicyPort{{
					PortRange: &npav1alpha1.PortRange{
						Protocol: v1.ProtocolTCP,
						Start:    80,
						End:      120,
					}}},
			}}
		})

	npaMultiPortEgressPodNsSelector := makeAdminNetworkPolicyCustom("multiport-egress-pod-ns", "foo",
		func(networkPolicy *npav1alpha1.AdminNetworkPolicy) {
			networkPolicy.Spec.Subject = npav1alpha1.AdminNetworkPolicySubject{Namespaces: &metav1.LabelSelector{}}
			networkPolicy.Spec.Priority = 10
			networkPolicy.Spec.Egress = []npav1alpha1.AdminNetworkPolicyEgressRule{{
				Action: npav1alpha1.AdminNetworkPolicyRuleActionAllow,
				To: []npav1alpha1.AdminNetworkPolicyEgressPeer{{
					Pods: &npav1alpha1.NamespacedPod{
						NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
						PodSelector:       metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
					},
				}},
				Ports: &[]npav1alpha1.AdminNetworkPolicyPort{{
					PortRange: &npav1alpha1.PortRange{
						Protocol: v1.ProtocolTCP,
						Start:    80,
						End:      120,
					}}},
			}}
		})

	npaMultiPortIngressPodNsSelector := makeAdminNetworkPolicyCustom("multiport-ingress-pod-ns", "bar",
		func(networkPolicy *npav1alpha1.AdminNetworkPolicy) {
			networkPolicy.Spec.Subject = npav1alpha1.AdminNetworkPolicySubject{Namespaces: &metav1.LabelSelector{}}
			networkPolicy.Spec.Priority = 10
			networkPolicy.Spec.Ingress = []npav1alpha1.AdminNetworkPolicyIngressRule{{
				Action: npav1alpha1.AdminNetworkPolicyRuleActionAllow,
				From: []npav1alpha1.AdminNetworkPolicyIngressPeer{{
					Pods: &npav1alpha1.NamespacedPod{
						NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
						PodSelector:       metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
					},
				}},
				Ports: &[]npav1alpha1.AdminNetworkPolicyPort{{
					PortRange: &npav1alpha1.PortRange{
						Protocol: v1.ProtocolTCP,
						Start:    80,
						End:      120,
					}}},
			}}
		})

	tests := []struct {
		name          string
		networkpolicy []*npav1alpha1.AdminNetworkPolicy
		namespace     []*v1.Namespace
		pod           []*v1.Pod
		node          []*v1.Node
		p             Packet
		expect        bool
	}{
		{
			name:          "no network policy",
			networkpolicy: []*npav1alpha1.AdminNetworkPolicy{},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB, podC, podD},
			p: Packet{
				srcIP:   net.ParseIP("192.168.1.11"),
				srcPort: 52345,
				dstIP:   net.ParseIP("192.168.2.22"),
				dstPort: 80,
				proto:   v1.ProtocolTCP,
			},
			expect: true,
		},
		{
			name:          "deny ingress",
			networkpolicy: []*npav1alpha1.AdminNetworkPolicy{npaDefaultDenyIngress},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB, podC, podD},
			p: Packet{
				srcIP:   net.ParseIP("192.168.1.11"),
				srcPort: 52345,
				dstIP:   net.ParseIP("192.168.2.22"),
				dstPort: 80,
				proto:   v1.ProtocolTCP,
			},
			expect: false,
		},
		{
			name:          "deny egress",
			networkpolicy: []*npav1alpha1.AdminNetworkPolicy{npaDefaultDenyEgress},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB, podC, podD},
			p: Packet{
				srcIP:   net.ParseIP("192.168.2.22"),
				srcPort: 52345,
				dstIP:   net.ParseIP("192.168.1.11"),
				dstPort: 80,
				proto:   v1.ProtocolTCP,
			},
			expect: false,
		},
		{
			name:          "allow all override deny ingress if it has higher priority",
			networkpolicy: []*npav1alpha1.AdminNetworkPolicy{npaDefaultDenyIngress, npaAllowAllIngress},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB, podC, podD},
			p: Packet{
				srcIP:   net.ParseIP("192.168.1.11"),
				srcPort: 52345,
				dstIP:   net.ParseIP("192.168.2.22"),
				dstPort: 80,
				proto:   v1.ProtocolTCP,
			},
			expect: true,
		},
		{
			name:          "allow ingress",
			networkpolicy: []*npav1alpha1.AdminNetworkPolicy{npaAllowAllIngressPod},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB, podC, podD},
			p: Packet{
				srcIP:   net.ParseIP("10.0.0.1"),
				srcPort: 52345,
				dstIP:   net.ParseIP("192.168.2.22"),
				dstPort: 80,
				proto:   v1.ProtocolTCP,
			},
			expect: true,
		},
		{
			name:          "multiport allow egress port",
			networkpolicy: []*npav1alpha1.AdminNetworkPolicy{npaDefaultDenyEgress, npaAllowMultiPortEgress},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB, podC, podD},
			p: Packet{
				srcIP:   net.ParseIP("192.168.1.11"),
				srcPort: 52345,
				dstIP:   net.ParseIP("192.168.2.22"),
				dstPort: 80,
				proto:   v1.ProtocolTCP,
			},
			expect: true,
		},
		{
			name:          "multiport allow egress node port",
			networkpolicy: []*npav1alpha1.AdminNetworkPolicy{npaDefaultDenyEgress, npaAllowMultiPortEgressNode},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB, podC, podD},
			p: Packet{
				srcIP:   net.ParseIP("192.168.1.11"),
				srcPort: 52345,
				dstIP:   net.ParseIP("192.168.2.22"),
				dstPort: 80,
				proto:   v1.ProtocolTCP,
			},
			expect: true,
		},
		{
			name:          "multiport deny egress port",
			networkpolicy: []*npav1alpha1.AdminNetworkPolicy{npaDefaultDenyEgress, npaAllowMultiPortEgress},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB, podC, podD},
			p: Packet{
				srcIP:   net.ParseIP("192.168.1.11"),
				srcPort: 52345,
				dstIP:   net.ParseIP("192.168.2.22"),
				dstPort: 30080,
				proto:   v1.ProtocolTCP,
			},
			expect: false,
		},
		{
			name:          "multiport allow egress",
			networkpolicy: []*npav1alpha1.AdminNetworkPolicy{npaDefaultDenyEgress, npaAllowMultiPortEgressCIDR},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB, podC, podD},
			p: Packet{
				srcIP:   net.ParseIP("192.168.1.11"),
				srcPort: 52345,
				dstIP:   net.ParseIP("192.168.2.22"),
				dstPort: 80,
				proto:   v1.ProtocolTCP,
			},
			expect: true,
		},
		{
			name:          "multiport allow egress port selector not match ns",
			networkpolicy: []*npav1alpha1.AdminNetworkPolicy{npaDefaultDenyEgress, npaAllowMultiPortEgressPodSelector},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB, podC, podD},
			p: Packet{
				srcIP:   net.ParseIP("192.168.1.11"),
				srcPort: 52345,
				dstIP:   net.ParseIP("192.168.2.22"),
				dstPort: 80,
				proto:   v1.ProtocolTCP,
			},
			expect: true,
		},
		{
			name:          "multiport allow egress ns selector",
			networkpolicy: []*npav1alpha1.AdminNetworkPolicy{npaDefaultDenyEgress, npaMultiPortEgressNsSelector},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB, podC, podD},
			p: Packet{
				srcIP:   net.ParseIP("192.168.1.11"),
				srcPort: 52345,
				dstIP:   net.ParseIP("192.168.2.22"),
				dstPort: 80,
				proto:   v1.ProtocolTCP,
			},
			expect: true,
		},
		{
			name:          "multiport allow egress ns selector fail",
			networkpolicy: []*npav1alpha1.AdminNetworkPolicy{npaDefaultDenyEgress, npaMultiPortEgressNsSelector},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB, podC, podD},
			p: Packet{
				srcIP:   net.ParseIP("192.168.1.11"),
				srcPort: 52345,
				dstIP:   net.ParseIP("192.168.3.33"),
				dstPort: 80,
				proto:   v1.ProtocolTCP,
			},
			expect: true,
		},
		{
			name:          "multiport allow egress ns and pod selector",
			networkpolicy: []*npav1alpha1.AdminNetworkPolicy{npaDefaultDenyEgress, npaMultiPortEgressPodNsSelector},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB, podC, podD},
			p: Packet{
				srcIP:   net.ParseIP("192.168.1.11"),
				srcPort: 52345,
				dstIP:   net.ParseIP("192.168.2.22"),
				dstPort: 80,
				proto:   v1.ProtocolTCP,
			},
			expect: true,
		},
		{
			name:          "multiport allow egress ns and pod selector fail",
			networkpolicy: []*npav1alpha1.AdminNetworkPolicy{npaDefaultDenyEgress, npaMultiPortEgressPodNsSelector},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB, podC, podD},
			p: Packet{
				srcIP:   net.ParseIP("192.168.1.11"),
				srcPort: 52345,
				dstIP:   net.ParseIP("192.168.3.33"),
				dstPort: 80,
				proto:   v1.ProtocolTCP,
			},
			expect: true,
		},
		{
			name:          "multiport allow ingress ns and pod selector",
			networkpolicy: []*npav1alpha1.AdminNetworkPolicy{npaDefaultDenyIngress, npaMultiPortIngressPodNsSelector},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB, podC, podD},
			p: Packet{
				srcIP:   net.ParseIP("192.168.1.11"),
				srcPort: 52345,
				dstIP:   net.ParseIP("192.168.2.22"),
				dstPort: 80,
				proto:   v1.ProtocolTCP,
			},
			expect: true,
		},
		{
			name:          "multiport allow ingress ns and pod selector fail",
			networkpolicy: []*npav1alpha1.AdminNetworkPolicy{npaDefaultDenyIngress, npaMultiPortIngressPodNsSelector},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB, podC, podD},
			p: Packet{
				srcIP:   net.ParseIP("192.168.1.11"),
				srcPort: 52345,
				dstIP:   net.ParseIP("192.168.4.44"),
				dstPort: 9080,
				proto:   v1.ProtocolTCP,
			},
			expect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := newTestController()
			// Add objects to the Store
			for _, n := range tt.networkpolicy {
				err := controller.adminNetworkpolicyStore.Add(n)
				if err != nil {
					t.Fatal(err)
				}
			}
			for _, n := range tt.namespace {
				err := controller.namespaceStore.Add(n)
				if err != nil {
					t.Fatal(err)
				}
			}
			for _, p := range tt.pod {
				err := controller.podStore.Add(p)
				if err != nil {
					t.Fatal(err)
				}
			}
			err := controller.nodeStore.Add(makeNode("testnode"))
			if err != nil {
				t.Fatal(err)
			}

			ok := controller.evaluatePacket(context.TODO(), tt.p)
			if ok != tt.expect {
				t.Errorf("expected %v got  %v", tt.expect, ok)
			}

		})
	}
}

func Test_evaluateAdminNetworkPolicyPort(t *testing.T) {
	tests := []struct {
		name               string
		networkPolicyPorts []npav1alpha1.AdminNetworkPolicyPort
		pod                *v1.Pod
		port               int
		protocol           v1.Protocol
		want               bool
	}{
		{
			name: "empty",
			pod:  makePod("test", "nstest", "192.168.1.1"),
			want: true,
		},
		{
			name: "match port",
			networkPolicyPorts: []npav1alpha1.AdminNetworkPolicyPort{{
				PortNumber: &npav1alpha1.Port{
					Protocol: v1.ProtocolTCP,
					Port:     80,
				},
			}},
			pod:      makePod("test", "nstest", "192.168.1.1"),
			port:     80,
			protocol: v1.ProtocolTCP,
			want:     true,
		},
		{
			name: "wrong port protocol",
			networkPolicyPorts: []npav1alpha1.AdminNetworkPolicyPort{{
				PortNumber: &npav1alpha1.Port{
					Protocol: v1.ProtocolTCP,
					Port:     80,
				},
			}},
			pod:      makePod("test", "nstest", "192.168.1.1"),
			port:     80,
			protocol: v1.ProtocolUDP,
			want:     false,
		},
		{
			name: "wrong port number",
			networkPolicyPorts: []npav1alpha1.AdminNetworkPolicyPort{{
				PortNumber: &npav1alpha1.Port{
					Protocol: v1.ProtocolTCP,
					Port:     80,
				},
			}},
			pod:      makePod("test", "nstest", "192.168.1.1"),
			port:     443,
			protocol: v1.ProtocolTCP,
			want:     false,
		},
		{
			name: "match port named",
			networkPolicyPorts: []npav1alpha1.AdminNetworkPolicyPort{{
				NamedPort: ptr.To[string]("http"),
			}},
			pod:      makePod("test", "nstest", "192.168.1.1"),
			port:     80,
			protocol: v1.ProtocolTCP,
			want:     true,
		},
		{
			name: "match port range",
			networkPolicyPorts: []npav1alpha1.AdminNetworkPolicyPort{{
				PortRange: &npav1alpha1.PortRange{
					Protocol: v1.ProtocolTCP,
					Start:    80,
					End:      120,
				},
			}},
			pod:      makePod("test", "nstest", "192.168.1.1"),
			port:     80,
			protocol: v1.ProtocolTCP,
			want:     true,
		},
		{
			name: "out port range",
			networkPolicyPorts: []npav1alpha1.AdminNetworkPolicyPort{{
				PortRange: &npav1alpha1.PortRange{
					Protocol: v1.ProtocolTCP,
					Start:    80,
					End:      120,
				},
			}},
			pod:      makePod("test", "nstest", "192.168.1.1"),
			port:     180,
			protocol: v1.ProtocolTCP,
			want:     false,
		},
		{
			name: "inside port range but wrong protocol",
			networkPolicyPorts: []npav1alpha1.AdminNetworkPolicyPort{{
				PortRange: &npav1alpha1.PortRange{
					Protocol: v1.ProtocolTCP,
					Start:    80,
					End:      120,
				},
			}},
			pod:      makePod("test", "nstest", "192.168.1.1"),
			port:     90,
			protocol: v1.ProtocolUDP,
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := evaluateAdminNetworkPolicyPort(tt.networkPolicyPorts, tt.pod, tt.port, tt.protocol); got != tt.want {
				t.Errorf("evaluateAdminNetworkPolicyPort() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestController_getAdminNetworkPoliciesForPod(t *testing.T) {
	_, err := logs.GlogSetter("4")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name          string
		networkpolicy *npav1alpha1.AdminNetworkPolicy
		want          bool
	}{
		{
			name:          "empty",
			networkpolicy: &npav1alpha1.AdminNetworkPolicy{},
			want:          false,
		},
		{
			name: "empty namespace selector matches all",
			networkpolicy: makeAdminNetworkPolicyCustom("anp", "bar",
				func(networkPolicy *npav1alpha1.AdminNetworkPolicy) {
					networkPolicy.Spec.Subject = npav1alpha1.AdminNetworkPolicySubject{
						Namespaces: &metav1.LabelSelector{},
					}
				},
			),
			want: true,
		},
		{
			name: "match namespace",
			networkpolicy: makeAdminNetworkPolicyCustom("anp", "foo",
				func(networkPolicy *npav1alpha1.AdminNetworkPolicy) {
					networkPolicy.Spec.Subject = npav1alpha1.AdminNetworkPolicySubject{
						Namespaces: &metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
					}
				},
			),
			want: true,
		},
		{
			name: "do not match namespace",
			networkpolicy: makeAdminNetworkPolicyCustom("anp", "foo",
				func(networkPolicy *npav1alpha1.AdminNetworkPolicy) {
					networkPolicy.Spec.Subject = npav1alpha1.AdminNetworkPolicySubject{
						Namespaces: &metav1.LabelSelector{MatchLabels: map[string]string{"c": "do not match"}},
					}
				},
			),
			want: false,
		},
		{
			name: "empty selectors matches all",
			networkpolicy: makeAdminNetworkPolicyCustom("anp", "bar",
				func(networkPolicy *npav1alpha1.AdminNetworkPolicy) {
					networkPolicy.Spec.Subject = npav1alpha1.AdminNetworkPolicySubject{
						Pods: &npav1alpha1.NamespacedPod{},
					}
				},
			),
			want: true,
		},
		{
			name: "match pod selectors",
			networkpolicy: makeAdminNetworkPolicyCustom("anp", "bar",
				func(networkPolicy *npav1alpha1.AdminNetworkPolicy) {
					networkPolicy.Spec.Subject = npav1alpha1.AdminNetworkPolicySubject{
						Pods: &npav1alpha1.NamespacedPod{
							PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
						},
					}
				},
			),
			want: true,
		},
		{
			name: "match namespace selectors",
			networkpolicy: makeAdminNetworkPolicyCustom("anp", "bar",
				func(networkPolicy *npav1alpha1.AdminNetworkPolicy) {
					networkPolicy.Spec.Subject = npav1alpha1.AdminNetworkPolicySubject{
						Pods: &npav1alpha1.NamespacedPod{
							NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
						},
					}
				},
			),
			want: true,
		},
		{
			name: "match namespace and selectors",
			networkpolicy: makeAdminNetworkPolicyCustom("anp", "bar",
				func(networkPolicy *npav1alpha1.AdminNetworkPolicy) {
					networkPolicy.Spec.Subject = npav1alpha1.AdminNetworkPolicySubject{
						Pods: &npav1alpha1.NamespacedPod{
							NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
							PodSelector:       metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
						},
					}
				},
			),
			want: true,
		},
		{
			name: "do not match namespace match pod",
			networkpolicy: makeAdminNetworkPolicyCustom("anp", "foo",
				func(networkPolicy *npav1alpha1.AdminNetworkPolicy) {
					networkPolicy.Spec.Subject = npav1alpha1.AdminNetworkPolicySubject{
						Pods: &npav1alpha1.NamespacedPod{
							NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"c": "do not match"}},
							PodSelector:       metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
						},
					}
				},
			),
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := newTestController()
			// Add objects to the Store
			err := controller.adminNetworkpolicyStore.Add(tt.networkpolicy)
			if err != nil {
				t.Fatal(err)
			}
			err = controller.namespaceStore.Add(makeNamespace("foo"))
			if err != nil {
				t.Fatal(err)
			}

			if got := controller.getAdminNetworkPoliciesForPod(context.TODO(), makePod("a", "foo", "192.168.1.11")); len(got) > 0 != tt.want {
				t.Errorf("Controller.getAdminNetworkPoliciesForPod() = %v, want %v", len(got) > 0, tt.want)
			}
		})
	}
}
