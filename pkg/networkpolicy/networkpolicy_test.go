package networkpolicy

import (
	"context"
	"net"
	"testing"

	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/component-base/logs"
	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"
)

type netpolTweak func(networkPolicy *networkingv1.NetworkPolicy)

func makeNetworkPolicyCustom(name, ns string, tweaks ...netpolTweak) *networkingv1.NetworkPolicy {
	networkPolicy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec:       networkingv1.NetworkPolicySpec{},
	}
	for _, fn := range tweaks {
		fn(networkPolicy)
	}
	return networkPolicy
}

func makePort(proto *v1.Protocol, port intstr.IntOrString, endPort int32) networkingv1.NetworkPolicyPort {
	r := networkingv1.NetworkPolicyPort{
		Protocol: proto,
		Port:     nil,
	}
	if port != intstr.FromInt32(0) && port != intstr.FromString("") && port != intstr.FromString("0") {
		r.Port = &port
	}
	if endPort != 0 {
		r.EndPort = ptr.To[int32](endPort)
	}
	return r
}

func TestSyncPacket(t *testing.T) {
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

	npDefaultDenyIngress := makeNetworkPolicyCustom("default-deny-ingress", "bar",
		func(networkPolicy *networkingv1.NetworkPolicy) {
			networkPolicy.Spec.PodSelector = metav1.LabelSelector{}
			networkPolicy.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}
		})

	npDefaultDenyEgress := makeNetworkPolicyCustom("default-deny-ingress", "bar",
		func(networkPolicy *networkingv1.NetworkPolicy) {
			networkPolicy.Spec.PodSelector = metav1.LabelSelector{}
			networkPolicy.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}
		})

	npAllowAllIngress := makeNetworkPolicyCustom("default-allow-ingress", "bar",
		func(networkPolicy *networkingv1.NetworkPolicy) {
			networkPolicy.Spec.PodSelector = metav1.LabelSelector{}
			networkPolicy.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}
			networkPolicy.Spec.Ingress = []networkingv1.NetworkPolicyIngressRule{}
		})

	npAllowAllIngressIPBlock := makeNetworkPolicyCustom("default-allow-ingress-ipBlock", "bar",
		func(networkPolicy *networkingv1.NetworkPolicy) {
			networkPolicy.Spec.PodSelector = metav1.LabelSelector{}
			networkPolicy.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}
			networkPolicy.Spec.Ingress = []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					IPBlock: &networkingv1.IPBlock{CIDR: "192.168.0.0/16"},
				}},
			}}
		})

	npMultiPortEgress := makeNetworkPolicyCustom("multiport-egress", "foo",
		func(networkPolicy *networkingv1.NetworkPolicy) {
			networkPolicy.Spec.PodSelector = metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}}
			networkPolicy.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}
			networkPolicy.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{{
				Ports: []networkingv1.NetworkPolicyPort{makePort(&protocolTCP, intstr.FromInt32(30000), 65537)},
				To:    []networkingv1.NetworkPolicyPeer{},
			}}
		})

	npMultiPortEgressIPBlock := makeNetworkPolicyCustom("multiport-egress", "foo",
		func(networkPolicy *networkingv1.NetworkPolicy) {
			networkPolicy.Spec.PodSelector = metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}}
			networkPolicy.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}
			networkPolicy.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{{
				To: []networkingv1.NetworkPolicyPeer{{
					IPBlock: &networkingv1.IPBlock{CIDR: "192.168.0.0/16"},
				}},
			}}
		})

	npMultiPortEgressPodSelector := makeNetworkPolicyCustom("multiport-egress", "foo",
		func(networkPolicy *networkingv1.NetworkPolicy) {
			networkPolicy.Spec.PodSelector = metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}}
			networkPolicy.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}
			networkPolicy.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{{
				To: []networkingv1.NetworkPolicyPeer{{
					PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
				}},
			}}
		})

	npMultiPortEgressNsSelector := makeNetworkPolicyCustom("multiport-egress-ns", "foo",
		func(networkPolicy *networkingv1.NetworkPolicy) {
			networkPolicy.Spec.PodSelector = metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}}
			networkPolicy.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}
			networkPolicy.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{{
				To: []networkingv1.NetworkPolicyPeer{{
					NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
				}},
			}}
		})

	npMultiPortEgressPodNsSelector := makeNetworkPolicyCustom("multiport-egress-pod-ns", "foo",
		func(networkPolicy *networkingv1.NetworkPolicy) {
			networkPolicy.Spec.PodSelector = metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}}
			networkPolicy.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}
			networkPolicy.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{{
				To: []networkingv1.NetworkPolicyPeer{{
					PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
					NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
				}},
			}}
		})

	npMultiPortIngressPodNsSelector := makeNetworkPolicyCustom("multiport-ingress-pod-ns", "bar",
		func(networkPolicy *networkingv1.NetworkPolicy) {
			networkPolicy.Spec.PodSelector = metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}}
			networkPolicy.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}
			networkPolicy.Spec.Ingress = []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
					NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
				}},
			}}
		})

	tests := []struct {
		name          string
		networkpolicy []*networkingv1.NetworkPolicy
		namespace     []*v1.Namespace
		pod           []*v1.Pod
		p             Packet
		expect        bool
	}{
		{
			name:          "no network policy",
			networkpolicy: []*networkingv1.NetworkPolicy{},
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
			networkpolicy: []*networkingv1.NetworkPolicy{npDefaultDenyIngress},
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
			networkpolicy: []*networkingv1.NetworkPolicy{npDefaultDenyEgress},
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
			name:          "deny egress on reply does not have effect",
			networkpolicy: []*networkingv1.NetworkPolicy{npDefaultDenyEgress},
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
			name:          "allow all override deny ingress",
			networkpolicy: []*networkingv1.NetworkPolicy{npDefaultDenyIngress, npAllowAllIngress},
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
			name:          "ip block override deny ingress",
			networkpolicy: []*networkingv1.NetworkPolicy{npDefaultDenyIngress, npAllowAllIngressIPBlock},
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
			name:          "ip block deny ingress",
			networkpolicy: []*networkingv1.NetworkPolicy{npAllowAllIngressIPBlock},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB, podC, podD},
			p: Packet{
				srcIP:   net.ParseIP("10.0.0.1"),
				srcPort: 52345,
				dstIP:   net.ParseIP("192.168.2.22"),
				dstPort: 80,
				proto:   v1.ProtocolTCP,
			},
			expect: false,
		},
		{
			name:          "multiport deny egress port",
			networkpolicy: []*networkingv1.NetworkPolicy{npDefaultDenyEgress, npMultiPortEgress},
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
			name:          "multiport allow egress port",
			networkpolicy: []*networkingv1.NetworkPolicy{npDefaultDenyEgress, npMultiPortEgress},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB, podC, podD},
			p: Packet{
				srcIP:   net.ParseIP("192.168.1.11"),
				srcPort: 52345,
				dstIP:   net.ParseIP("192.168.2.22"),
				dstPort: 30080,
				proto:   v1.ProtocolTCP,
			},
			expect: true,
		},
		{
			name:          "multiport allow egress",
			networkpolicy: []*networkingv1.NetworkPolicy{npDefaultDenyEgress, npMultiPortEgress, npMultiPortEgressIPBlock},
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
			networkpolicy: []*networkingv1.NetworkPolicy{npDefaultDenyEgress, npMultiPortEgress, npMultiPortEgressPodSelector},
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
			name:          "multiport allow egress port selector not match pod selector",
			networkpolicy: []*networkingv1.NetworkPolicy{npDefaultDenyEgress, npMultiPortEgress, npMultiPortEgressPodSelector},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB, podC, podD},
			p: Packet{
				srcIP:   net.ParseIP("192.168.1.11"),
				srcPort: 52345,
				dstIP:   net.ParseIP("192.168.3.33"),
				dstPort: 80,
				proto:   v1.ProtocolTCP,
			},
			expect: false,
		},
		{
			name:          "multiport allow egress ns selector",
			networkpolicy: []*networkingv1.NetworkPolicy{npDefaultDenyEgress, npMultiPortEgress, npMultiPortEgressNsSelector},
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
			networkpolicy: []*networkingv1.NetworkPolicy{npDefaultDenyEgress, npMultiPortEgress, npMultiPortEgressNsSelector},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB, podC, podD},
			p: Packet{
				srcIP:   net.ParseIP("192.168.1.11"),
				srcPort: 52345,
				dstIP:   net.ParseIP("192.168.3.33"),
				dstPort: 80,
				proto:   v1.ProtocolTCP,
			},
			expect: false,
		},
		{
			name:          "multiport allow egress ns and pod selector",
			networkpolicy: []*networkingv1.NetworkPolicy{npDefaultDenyEgress, npMultiPortEgress, npMultiPortEgressPodNsSelector},
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
			networkpolicy: []*networkingv1.NetworkPolicy{npDefaultDenyEgress, npMultiPortEgress, npMultiPortEgressPodNsSelector},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB, podC, podD},
			p: Packet{
				srcIP:   net.ParseIP("192.168.1.11"),
				srcPort: 52345,
				dstIP:   net.ParseIP("192.168.3.33"),
				dstPort: 80,
				proto:   v1.ProtocolTCP,
			},
			expect: false,
		},
		{
			name:          "multiport allow ingress ns and pod selector",
			networkpolicy: []*networkingv1.NetworkPolicy{npDefaultDenyIngress, npMultiPortIngressPodNsSelector},
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
			networkpolicy: []*networkingv1.NetworkPolicy{npDefaultDenyIngress, npMultiPortIngressPodNsSelector},
			namespace:     []*v1.Namespace{makeNamespace("foo"), makeNamespace("bar")},
			pod:           []*v1.Pod{podA, podB, podC, podD},
			p: Packet{
				srcIP:   net.ParseIP("192.168.1.11"),
				srcPort: 52345,
				dstIP:   net.ParseIP("192.168.4.44"),
				dstPort: 80,
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
				err := controller.networkpolicyStore.Add(n)
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

			ok := controller.evaluatePacket(context.TODO(), tt.p)
			if ok != tt.expect {
				t.Errorf("expected %v got  %v", ok, tt.expect)
			}

		})
	}
}

func TestController_evaluateSelectors(t *testing.T) {
	tests := []struct {
		name            string
		networkpolicies []*networkingv1.NetworkPolicy
		namespaces      []*v1.Namespace
		pods            []*v1.Pod
		peerPodSelector *metav1.LabelSelector
		peerNSSelector  *metav1.LabelSelector
		pod             *v1.Pod
		policyNs        string
		want            bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestController()
			// Add objects to the Store
			for _, n := range tt.networkpolicies {
				err := c.networkpolicyStore.Add(n)
				if err != nil {
					t.Fatal(err)
				}
			}
			for _, n := range tt.namespaces {
				err := c.namespaceStore.Add(n)
				if err != nil {
					t.Fatal(err)
				}
			}
			for _, p := range tt.pods {
				err := c.podStore.Add(p)
				if err != nil {
					t.Fatal(err)
				}
			}
			if got := c.evaluateSelectors(context.TODO(), tt.peerPodSelector, tt.peerNSSelector, tt.pod, tt.policyNs); got != tt.want {
				t.Errorf("Controller.evaluateSelectors() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestController_evaluateIPBlocks(t *testing.T) {
	tests := []struct {
		name    string
		ipBlock *networkingv1.IPBlock
		ip      net.IP
		want    bool
	}{
		{
			name: "empty",
			want: true,
		},
		{
			name:    "match cidr",
			ipBlock: &networkingv1.IPBlock{CIDR: "192.168.0.0/24"},
			ip:      net.ParseIP("192.168.0.1"),
			want:    true,
		},
		{
			name:    "no match cidr",
			ipBlock: &networkingv1.IPBlock{CIDR: "192.168.0.0/24"},
			ip:      net.ParseIP("10.0.0.1"),
			want:    false,
		},
		{
			name:    "match cidr and not except",
			ipBlock: &networkingv1.IPBlock{CIDR: "192.168.0.0/24", Except: []string{"192.168.1.0/24"}},
			ip:      net.ParseIP("192.168.0.1"),
			want:    true,
		},
		{
			name:    "match cidr and  except",
			ipBlock: &networkingv1.IPBlock{CIDR: "192.168.0.0/24", Except: []string{"192.168.1.0/24"}},
			ip:      net.ParseIP("192.168.1.1"),
			want:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestController()
			if got := c.evaluateIPBlocks(tt.ipBlock, tt.ip); got != tt.want {
				t.Errorf("Controller.evaluateIPBlocks() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestController_evaluatePorts(t *testing.T) {
	tests := []struct {
		name               string
		networkPolicyPorts []networkingv1.NetworkPolicyPort
		pod                *v1.Pod
		port               int
		protocol           v1.Protocol
		want               bool
	}{
		{
			name: "empty",
			want: true,
		},
		{
			name:               "match TCP",
			networkPolicyPorts: []networkingv1.NetworkPolicyPort{makePort(&protocolTCP, intstr.FromInt32(30000), 0)},
			port:               30000,
			protocol:           protocolTCP,
			want:               true,
		},
		{
			name:               "match UDP",
			networkPolicyPorts: []networkingv1.NetworkPolicyPort{makePort(&protocolUDP, intstr.FromInt32(30000), 0)},
			port:               30000,
			protocol:           protocolUDP,
			want:               true,
		},
		{
			name:               "no match TCP",
			networkPolicyPorts: []networkingv1.NetworkPolicyPort{makePort(&protocolTCP, intstr.FromInt32(30000), 0)},
			port:               138,
			protocol:           protocolTCP,
			want:               false,
		},
		{
			name:               "no match UDP",
			networkPolicyPorts: []networkingv1.NetworkPolicyPort{makePort(&protocolUDP, intstr.FromInt32(30000), 0)},
			port:               138,
			protocol:           protocolUDP,
			want:               false,
		},
		{
			name:               "match TCP range",
			networkPolicyPorts: []networkingv1.NetworkPolicyPort{makePort(&protocolTCP, intstr.FromInt32(30000), 65537)},
			port:               30138,
			protocol:           protocolTCP,
			want:               true,
		},
		{
			name:               "match UDP range",
			networkPolicyPorts: []networkingv1.NetworkPolicyPort{makePort(&protocolUDP, intstr.FromInt32(30000), 65537)},
			port:               30138,
			protocol:           protocolUDP,
			want:               true,
		},
		{
			name:               "no match TCP range",
			networkPolicyPorts: []networkingv1.NetworkPolicyPort{makePort(&protocolTCP, intstr.FromInt32(30000), 65537)},
			port:               138,
			protocol:           protocolTCP,
			want:               false,
		},
		{
			name:               "no match UDP range",
			networkPolicyPorts: []networkingv1.NetworkPolicyPort{makePort(&protocolUDP, intstr.FromInt32(30000), 65537)},
			port:               138,
			protocol:           protocolUDP,
			want:               false,
		},
		{
			name:               "match TCP named port",
			networkPolicyPorts: []networkingv1.NetworkPolicyPort{makePort(&protocolTCP, intstr.FromString("http"), 0)},
			pod:                makePod("a", "b", "192.168.1.1"),
			port:               80,
			protocol:           protocolTCP,
			want:               true,
		},
		{
			name:               "no match UDP named port",
			networkPolicyPorts: []networkingv1.NetworkPolicyPort{makePort(&protocolUDP, intstr.FromString("http"), 0)},
			pod:                makePod("a", "b", "192.168.1.1"),
			port:               80,
			protocol:           protocolTCP,
			want:               false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestController()
			if got := c.evaluatePorts(tt.networkPolicyPorts, tt.pod, tt.port, tt.protocol); got != tt.want {
				t.Errorf("Controller.evaluatePorts() = %v, want %v", got, tt.want)
			}
		})
	}
}
