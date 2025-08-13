package pipeline

import (
	"context"
	"net"
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/component-base/logs"
	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/kube-network-policies/pkg/api"
	"sigs.k8s.io/kube-network-policies/pkg/network"
	npav1alpha1 "sigs.k8s.io/network-policy-api/apis/v1alpha1"
	npaclientfake "sigs.k8s.io/network-policy-api/pkg/client/clientset/versioned/fake"
	npainformers "sigs.k8s.io/network-policy-api/pkg/client/informers/externalversions"
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
		p             network.Packet
		expect        Verdict
	}{
		{
			name:          "no network policy",
			networkpolicy: []*npav1alpha1.AdminNetworkPolicy{},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB, podC, podD},
			p: network.Packet{
				SrcIP:   net.ParseIP("192.168.1.11"),
				SrcPort: 52345,
				DstIP:   net.ParseIP("192.168.2.22"),
				DstPort: 80,
				Proto:   v1.ProtocolTCP,
			},
			expect: VerdictNext,
		},
		{
			name:          "deny ingress",
			networkpolicy: []*npav1alpha1.AdminNetworkPolicy{npaDefaultDenyIngress},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB, podC, podD},
			p: network.Packet{
				SrcIP:   net.ParseIP("192.168.1.11"),
				SrcPort: 52345,
				DstIP:   net.ParseIP("192.168.2.22"),
				DstPort: 80,
				Proto:   v1.ProtocolTCP,
			},
			expect: VerdictDeny,
		},
		{
			name:          "deny egress",
			networkpolicy: []*npav1alpha1.AdminNetworkPolicy{npaDefaultDenyEgress},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB, podC, podD},
			p: network.Packet{
				SrcIP:   net.ParseIP("192.168.2.22"),
				SrcPort: 52345,
				DstIP:   net.ParseIP("192.168.1.11"),
				DstPort: 80,
				Proto:   v1.ProtocolTCP,
			},
			expect: VerdictDeny,
		},
		{
			name:          "allow all override deny ingress if it has higher priority",
			networkpolicy: []*npav1alpha1.AdminNetworkPolicy{npaDefaultDenyIngress, npaAllowAllIngress},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB, podC, podD},
			p: network.Packet{
				SrcIP:   net.ParseIP("192.168.1.11"),
				SrcPort: 52345,
				DstIP:   net.ParseIP("192.168.2.22"),
				DstPort: 80,
				Proto:   v1.ProtocolTCP,
			},
			expect: VerdictNext,
		},
		{
			name:          "allow ingress",
			networkpolicy: []*npav1alpha1.AdminNetworkPolicy{npaAllowAllIngressPod},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB, podC, podD},
			p: network.Packet{
				SrcIP:   net.ParseIP("10.0.0.1"),
				SrcPort: 52345,
				DstIP:   net.ParseIP("192.168.2.22"),
				DstPort: 80,
				Proto:   v1.ProtocolTCP,
			},
			expect: VerdictNext,
		},
		{
			name:          "multiport allow egress port",
			networkpolicy: []*npav1alpha1.AdminNetworkPolicy{npaDefaultDenyEgress, npaAllowMultiPortEgress},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB, podC, podD},
			p: network.Packet{
				SrcIP:   net.ParseIP("192.168.1.11"),
				SrcPort: 52345,
				DstIP:   net.ParseIP("192.168.2.22"),
				DstPort: 80,
				Proto:   v1.ProtocolTCP,
			},
			expect: VerdictNext,
		},
		{
			name:          "multiport allow egress node port",
			networkpolicy: []*npav1alpha1.AdminNetworkPolicy{npaDefaultDenyEgress, npaAllowMultiPortEgressNode},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB, podC, podD},
			p: network.Packet{
				SrcIP:   net.ParseIP("192.168.1.11"),
				SrcPort: 52345,
				DstIP:   net.ParseIP("192.168.2.22"),
				DstPort: 80,
				Proto:   v1.ProtocolTCP,
			},
			expect: VerdictNext,
		},
		{
			name:          "multiport deny egress port",
			networkpolicy: []*npav1alpha1.AdminNetworkPolicy{npaDefaultDenyEgress, npaAllowMultiPortEgress},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB, podC, podD},
			p: network.Packet{
				SrcIP:   net.ParseIP("192.168.1.11"),
				SrcPort: 52345,
				DstIP:   net.ParseIP("192.168.2.22"),
				DstPort: 30080,
				Proto:   v1.ProtocolTCP,
			},
			expect: VerdictDeny,
		},
		{
			name:          "multiport allow egress",
			networkpolicy: []*npav1alpha1.AdminNetworkPolicy{npaDefaultDenyEgress, npaAllowMultiPortEgressCIDR},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB, podC, podD},
			p: network.Packet{
				SrcIP:   net.ParseIP("192.168.1.11"),
				SrcPort: 52345,
				DstIP:   net.ParseIP("192.168.2.22"),
				DstPort: 80,
				Proto:   v1.ProtocolTCP,
			},
			expect: VerdictNext,
		},
		{
			name:          "multiport allow egress port selector not match ns",
			networkpolicy: []*npav1alpha1.AdminNetworkPolicy{npaDefaultDenyEgress, npaAllowMultiPortEgressPodSelector},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB, podC, podD},
			p: network.Packet{
				SrcIP:   net.ParseIP("192.168.1.11"),
				SrcPort: 52345,
				DstIP:   net.ParseIP("192.168.2.22"),
				DstPort: 80,
				Proto:   v1.ProtocolTCP,
			},
			expect: VerdictNext,
		},
		{
			name:          "multiport allow egress ns selector",
			networkpolicy: []*npav1alpha1.AdminNetworkPolicy{npaDefaultDenyEgress, npaMultiPortEgressNsSelector},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB, podC, podD},
			p: network.Packet{
				SrcIP:   net.ParseIP("192.168.1.11"),
				SrcPort: 52345,
				DstIP:   net.ParseIP("192.168.2.22"),
				DstPort: 80,
				Proto:   v1.ProtocolTCP,
			},
			expect: VerdictNext,
		},
		{
			name:          "multiport allow egress ns selector fail",
			networkpolicy: []*npav1alpha1.AdminNetworkPolicy{npaDefaultDenyEgress, npaMultiPortEgressNsSelector},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB, podC, podD},
			p: network.Packet{
				SrcIP:   net.ParseIP("192.168.1.11"),
				SrcPort: 52345,
				DstIP:   net.ParseIP("192.168.3.33"),
				DstPort: 80,
				Proto:   v1.ProtocolTCP,
			},
			expect: VerdictNext,
		},
		{
			name:          "multiport allow egress ns and pod selector",
			networkpolicy: []*npav1alpha1.AdminNetworkPolicy{npaDefaultDenyEgress, npaMultiPortEgressPodNsSelector},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB, podC, podD},
			p: network.Packet{
				SrcIP:   net.ParseIP("192.168.1.11"),
				SrcPort: 52345,
				DstIP:   net.ParseIP("192.168.2.22"),
				DstPort: 80,
				Proto:   v1.ProtocolTCP,
			},
			expect: VerdictNext,
		},
		{
			name:          "multiport allow egress ns and pod selector fail",
			networkpolicy: []*npav1alpha1.AdminNetworkPolicy{npaDefaultDenyEgress, npaMultiPortEgressPodNsSelector},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB, podC, podD},
			p: network.Packet{
				SrcIP:   net.ParseIP("192.168.1.11"),
				SrcPort: 52345,
				DstIP:   net.ParseIP("192.168.3.33"),
				DstPort: 80,
				Proto:   v1.ProtocolTCP,
			},
			expect: VerdictNext,
		},
		{
			name:          "multiport allow ingress ns and pod selector",
			networkpolicy: []*npav1alpha1.AdminNetworkPolicy{npaDefaultDenyIngress, npaMultiPortIngressPodNsSelector},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB, podC, podD},
			p: network.Packet{
				SrcIP:   net.ParseIP("192.168.1.11"),
				SrcPort: 52345,
				DstIP:   net.ParseIP("192.168.2.22"),
				DstPort: 80,
				Proto:   v1.ProtocolTCP,
			},
			expect: VerdictNext,
		},
		{
			name:          "multiport allow ingress ns and pod selector fail",
			networkpolicy: []*npav1alpha1.AdminNetworkPolicy{npaDefaultDenyIngress, npaMultiPortIngressPodNsSelector},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB, podC, podD},
			p: network.Packet{
				SrcIP:   net.ParseIP("192.168.1.11"),
				SrcPort: 52345,
				DstIP:   net.ParseIP("192.168.4.44"),
				DstPort: 9080,
				Proto:   v1.ProtocolTCP,
			},
			expect: VerdictDeny,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			npaClient := npaclientfake.NewSimpleClientset()
			npaInformerFactory := npainformers.NewSharedInformerFactory(npaClient, 0)
			adminNetworkPolicyInformer := npaInformerFactory.Policy().V1alpha1().AdminNetworkPolicies()
			adminNetworkpolicyStore := adminNetworkPolicyInformer.Informer().GetStore()

			// Add objects to the Store
			for _, n := range tt.networkpolicy {
				err := adminNetworkpolicyStore.Add(n)
				if err != nil {
					t.Fatal(err)
				}
			}

			getPodInfo := func(podIP string) (*api.PodInfo, bool) {
				for _, p := range tt.pod {
					for _, ip := range p.Status.PodIPs {
						if ip.IP == podIP {
							for _, n := range tt.namespace {
								if n.Name == p.Namespace {
									return api.PodAndNamespaceAndNodeToPodInfo(p, n, makeNode("testnode"), ""), true
								}
							}
						}
					}
				}
				return nil, false
			}

			evaluator := NewAdminNetworkPolicyEvaluator(getPodInfo,
				adminNetworkPolicyInformer.Lister(),
			)

			verdict, err := evaluator.Evaluate(context.TODO(), &tt.p)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if verdict != tt.expect {
				t.Errorf("got %v, but expected  %v", verdict, tt.expect)
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
			podInfo := api.PodAndNamespaceAndNodeToPodInfo(tt.pod, makeNamespace("foo"), makeNode("testnode"), "id")
			if got := evaluateAdminNetworkPolicyPort(tt.networkPolicyPorts, podInfo, tt.port, tt.protocol); got != tt.want {
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
			name: "match namespace label",
			networkpolicy: makeAdminNetworkPolicyCustom("anp", "bar",
				func(networkPolicy *npav1alpha1.AdminNetworkPolicy) {
					networkPolicy.Spec.Subject = npav1alpha1.AdminNetworkPolicySubject{
						Pods: &npav1alpha1.NamespacedPod{
							NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "foo"}},
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
			podInfo := api.PodAndNamespaceAndNodeToPodInfo(makePod("a", "foo", "192.168.1.11"), makeNamespace("foo"), makeNode("testnode"), "id")
			if got := getAdminNetworkPoliciesForPod(podInfo, []*npav1alpha1.AdminNetworkPolicy{tt.networkpolicy}); len(got) > 0 != tt.want {
				t.Errorf("Controller.getAdminNetworkPoliciesForPod() = %v, want %v", len(got) > 0, tt.want)
			}
		})
	}
}

/*

func TestController_evaluateAdminEgress_DomainNames(t *testing.T) {
	podA := makePod("a", "foo", "192.168.1.11")
	ipAllow := net.ParseIP("10.0.0.1")
	ipDeny := net.ParseIP("10.0.0.2")
	ipOther := net.ParseIP("10.0.0.3")
	domainAllow := "allow.example.com"
	domainDeny := "deny.example.com"
	domainWildcard := "*.wild.com"
	domainSpecificWild := "test.wild.com"

	tests := []struct {
		name           string
		policy         *npav1alpha1.AdminNetworkPolicy
		dstIP          net.IP
		expectedAction npav1alpha1.AdminNetworkPolicyRuleAction
	}{
		{
			name: "Allow rule matches domain and IP",
			policy: makeAdminNetworkPolicyCustom("allow-domain", "foo", func(p *npav1alpha1.AdminNetworkPolicy) {
				p.Spec.Priority = 10
				p.Spec.Subject.Namespaces = &metav1.LabelSelector{}
				p.Spec.Egress = []npav1alpha1.AdminNetworkPolicyEgressRule{{
					Action: npav1alpha1.AdminNetworkPolicyRuleActionAllow,
					To: []npav1alpha1.AdminNetworkPolicyEgressPeer{{
						DomainNames: []npav1alpha1.DomainName{npav1alpha1.DomainName(domainAllow)},
					}},
				}}
			}),
			dstIP:          ipAllow,
			expectedAction: npav1alpha1.AdminNetworkPolicyRuleActionAllow,
		},
		{
			name: "Allow rule matches domain but not IP",
			policy: makeAdminNetworkPolicyCustom("allow-domain-wrong-ip", "foo", func(p *npav1alpha1.AdminNetworkPolicy) {
				p.Spec.Priority = 10
				p.Spec.Subject.Namespaces = &metav1.LabelSelector{}
				p.Spec.Egress = []npav1alpha1.AdminNetworkPolicyEgressRule{{
					Action: npav1alpha1.AdminNetworkPolicyRuleActionAllow,
					To: []npav1alpha1.AdminNetworkPolicyEgressPeer{{
						DomainNames: []npav1alpha1.DomainName{npav1alpha1.DomainName(domainAllow)},
					}},
				}}
			}),
			dstIP:          ipOther,                                      // IP not in cache for domainAllow
			expectedAction: npav1alpha1.AdminNetworkPolicyRuleActionPass, // Rule doesn't match, pass to next rule/policy
		},
		{
			name: "Deny rule matches domain and IP",
			policy: makeAdminNetworkPolicyCustom("deny-domain", "foo", func(p *npav1alpha1.AdminNetworkPolicy) {
				p.Spec.Priority = 10
				p.Spec.Subject.Namespaces = &metav1.LabelSelector{}
				p.Spec.Egress = []npav1alpha1.AdminNetworkPolicyEgressRule{{
					Action: npav1alpha1.AdminNetworkPolicyRuleActionDeny,
					To: []npav1alpha1.AdminNetworkPolicyEgressPeer{{
						DomainNames: []npav1alpha1.DomainName{npav1alpha1.DomainName(domainDeny)},
					}},
				}}
			}),
			dstIP:          ipDeny,
			expectedAction: npav1alpha1.AdminNetworkPolicyRuleActionDeny,
		},
		{
			name: "Rule domain does not match cached domains",
			policy: makeAdminNetworkPolicyCustom("nomatch-domain", "foo", func(p *npav1alpha1.AdminNetworkPolicy) {
				p.Spec.Priority = 10
				p.Spec.Subject.Namespaces = &metav1.LabelSelector{}
				p.Spec.Egress = []npav1alpha1.AdminNetworkPolicyEgressRule{{
					Action: npav1alpha1.AdminNetworkPolicyRuleActionAllow,
					To: []npav1alpha1.AdminNetworkPolicyEgressPeer{{
						DomainNames: []npav1alpha1.DomainName{"other.example.com"},
					}},
				}}
			}),
			dstIP:          ipAllow,
			expectedAction: npav1alpha1.AdminNetworkPolicyRuleActionPass, // Rule doesn't match
		},
		{
			name: "Multiple domains in rule, one matches",
			policy: makeAdminNetworkPolicyCustom("multi-domain", "foo", func(p *npav1alpha1.AdminNetworkPolicy) {
				p.Spec.Priority = 10
				p.Spec.Subject.Namespaces = &metav1.LabelSelector{}
				p.Spec.Egress = []npav1alpha1.AdminNetworkPolicyEgressRule{{
					Action: npav1alpha1.AdminNetworkPolicyRuleActionAllow,
					To: []npav1alpha1.AdminNetworkPolicyEgressPeer{{
						DomainNames: []npav1alpha1.DomainName{
							"other.example.com",
							npav1alpha1.DomainName(domainAllow), // This one matches
						},
					}},
				}}
			}),
			dstIP:          ipAllow,
			expectedAction: npav1alpha1.AdminNetworkPolicyRuleActionAllow,
		},
		{
			name: "Wildcard domain matches IP",
			policy: makeAdminNetworkPolicyCustom("wildcard-domain", "foo", func(p *npav1alpha1.AdminNetworkPolicy) {
				p.Spec.Priority = 10
				p.Spec.Subject.Namespaces = &metav1.LabelSelector{}
				p.Spec.Egress = []npav1alpha1.AdminNetworkPolicyEgressRule{{
					Action: npav1alpha1.AdminNetworkPolicyRuleActionAllow,
					To: []npav1alpha1.AdminNetworkPolicyEgressPeer{{
						// Simulate how the cache lookup might work for a wildcard
						// The actual cache logic is more complex (reversed domains)
						// Here we rely on the mock's ContainsIP behavior
						DomainNames: []npav1alpha1.DomainName{npav1alpha1.DomainName(domainWildcard)},
					}},
				}}
			}),
			dstIP:          ipAllow, // This IP is associated with test.wild.com in the mock cache
			expectedAction: npav1alpha1.AdminNetworkPolicyRuleActionAllow,
		},
		{
			name: "Wildcard domain does not match IP",
			policy: makeAdminNetworkPolicyCustom("wildcard-domain-no-ip", "foo", func(p *npav1alpha1.AdminNetworkPolicy) {
				p.Spec.Priority = 10
				p.Spec.Subject.Namespaces = &metav1.LabelSelector{}
				p.Spec.Egress = []npav1alpha1.AdminNetworkPolicyEgressRule{{
					Action: npav1alpha1.AdminNetworkPolicyRuleActionAllow,
					To: []npav1alpha1.AdminNetworkPolicyEgressPeer{{
						DomainNames: []npav1alpha1.DomainName{npav1alpha1.DomainName(domainWildcard)},
					}},
				}}
			}),
			dstIP:          ipOther, // This IP is not associated with any *.wild.com domain
			expectedAction: npav1alpha1.AdminNetworkPolicyRuleActionPass,
		},
		{
			name: "Rule with multiple peer types, domain matches",
			policy: makeAdminNetworkPolicyCustom("multi-peer-domain", "foo", func(p *npav1alpha1.AdminNetworkPolicy) {
				p.Spec.Priority = 10
				p.Spec.Subject.Namespaces = &metav1.LabelSelector{}
				p.Spec.Egress = []npav1alpha1.AdminNetworkPolicyEgressRule{{
					Action: npav1alpha1.AdminNetworkPolicyRuleActionAllow,
					To: []npav1alpha1.AdminNetworkPolicyEgressPeer{
						{Networks: []npav1alpha1.CIDR{"192.0.2.0/24"}},                               // Doesn't match dstIP
						{DomainNames: []npav1alpha1.DomainName{npav1alpha1.DomainName(domainAllow)}}, // Matches dstIP
					},
				}}
			}),
			dstIP:          ipAllow,
			expectedAction: npav1alpha1.AdminNetworkPolicyRuleActionAllow,
		},
		{
			name: "Rule with multiple peer types, domain does not match",
			policy: makeAdminNetworkPolicyCustom("multi-peer-no-domain", "foo", func(p *npav1alpha1.AdminNetworkPolicy) {
				p.Spec.Priority = 10
				p.Spec.Subject.Namespaces = &metav1.LabelSelector{}
				p.Spec.Egress = []npav1alpha1.AdminNetworkPolicyEgressRule{{
					Action: npav1alpha1.AdminNetworkPolicyRuleActionAllow,
					To: []npav1alpha1.AdminNetworkPolicyEgressPeer{
						{Networks: []npav1alpha1.CIDR{"192.0.2.0/24"}},               // Doesn't match dstIP
						{DomainNames: []npav1alpha1.DomainName{"other.example.com"}}, // Doesn't match dstIP
					},
				}}
			}),
			dstIP:          ipAllow,
			expectedAction: npav1alpha1.AdminNetworkPolicyRuleActionPass, // No peer in the rule matches
		},
		{
			name: "Rule with deny all, domain matches",
			policy: makeAdminNetworkPolicyCustom("deny-all-domain", "foo", func(p *npav1alpha1.AdminNetworkPolicy) {
				p.Spec.Priority = 10
				p.Spec.Subject.Namespaces = &metav1.LabelSelector{}
				p.Spec.Egress = []npav1alpha1.AdminNetworkPolicyEgressRule{{
					Action: npav1alpha1.AdminNetworkPolicyRuleActionAllow,
					To: []npav1alpha1.AdminNetworkPolicyEgressPeer{
						{DomainNames: []npav1alpha1.DomainName{npav1alpha1.DomainName(domainAllow)}}, // Doesn't match dstIP
					},
				}, {
					Action: npav1alpha1.AdminNetworkPolicyRuleActionDeny,
					To: []npav1alpha1.AdminNetworkPolicyEgressPeer{
						{Networks: []npav1alpha1.CIDR{"0.0.0.0/0"}}, // Doesn't match dstIP
					},
				}}
			}),
			dstIP:          ipAllow,
			expectedAction: npav1alpha1.AdminNetworkPolicyRuleActionAllow, // No peer in the rule matches
		},
		{
			name: "Rule with deny all, domain does not match",
			policy: makeAdminNetworkPolicyCustom("deny-all-no-domain", "foo", func(p *npav1alpha1.AdminNetworkPolicy) {
				p.Spec.Priority = 10
				p.Spec.Subject.Namespaces = &metav1.LabelSelector{}
				p.Spec.Egress = []npav1alpha1.AdminNetworkPolicyEgressRule{{
					Action: npav1alpha1.AdminNetworkPolicyRuleActionAllow,
					To: []npav1alpha1.AdminNetworkPolicyEgressPeer{
						{DomainNames: []npav1alpha1.DomainName{npav1alpha1.DomainName(domainAllow)}}, // Doesn't match dstIP
					},
				}, {
					Action: npav1alpha1.AdminNetworkPolicyRuleActionDeny,
					To: []npav1alpha1.AdminNetworkPolicyEgressPeer{
						{Networks: []npav1alpha1.CIDR{"0.0.0.0/0"}}, // Doesn't match dstIP
					},
				}}
			}),
			dstIP:          ipOther,
			expectedAction: npav1alpha1.AdminNetworkPolicyRuleActionDeny, // No peer in the rule matches
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a controller instance and inject the mock cache
			controller := newTestController(Config{AdminNetworkPolicy: true})
			controller.domainCache.cache.add(domainAllow, []net.IP{ipAllow}, int(maxTTL.Seconds()))
			controller.domainCache.cache.add(domainDeny, []net.IP{ipDeny}, int(maxTTL.Seconds()))
			controller.domainCache.cache.add(domainSpecificWild, []net.IP{ipAllow}, int(maxTTL.Seconds()))

			// Add necessary objects to stores (simplified for this test)
			err := controller.namespaceStore.Add(makeNamespace("foo"))
			if err != nil {
				t.Fatalf("Failed to add namespace: %v", err)
			}
			err = controller.podStore.Add(podA)
			if err != nil {
				t.Fatalf("Failed to add pod: %v", err)
			}

			// Call the function under test
			action := controller.evaluateAdminEgress(
				[]*npav1alpha1.AdminNetworkPolicy{tt.policy}, // Pass the single policy
				podA, // Source pod (can be nil if not needed for other peer types)
				tt.dstIP,
				80,             // Arbitrary port
				v1.ProtocolTCP, // Arbitrary protocol
			)

			// Assert the result
			if action != tt.expectedAction {
				t.Errorf("evaluateAdminEgress() = %v, want %v", action, tt.expectedAction)
			}
		})
	}
}

*/
