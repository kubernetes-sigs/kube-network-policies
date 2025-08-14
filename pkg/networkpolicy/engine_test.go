// SPDX-License-Identifier: APACHE-2.0

package networkpolicy

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"sigs.k8s.io/kube-network-policies/pkg/api"
	"sigs.k8s.io/kube-network-policies/pkg/network"

	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/component-base/logs"
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

// mockPolicyEvaluator is a mock implementation of PolicyEvaluator for testing.
type mockPolicyEvaluator struct {
	name            string
	evaluateIngress func(ctx context.Context, p *network.Packet, srcPod, dstPod *api.PodInfo) (Verdict, error)
	evaluateEgress  func(ctx context.Context, p *network.Packet, srcPod, dstPod *api.PodInfo) (Verdict, error)
}

func (m *mockPolicyEvaluator) Name() string {
	return m.name
}

func (m *mockPolicyEvaluator) EvaluateIngress(ctx context.Context, p *network.Packet, srcPod, dstPod *api.PodInfo) (Verdict, error) {
	if m.evaluateIngress != nil {
		return m.evaluateIngress(ctx, p, srcPod, dstPod)
	}
	return VerdictNext, nil
}

func (m *mockPolicyEvaluator) EvaluateEgress(ctx context.Context, p *network.Packet, srcPod, dstPod *api.PodInfo) (Verdict, error) {
	if m.evaluateEgress != nil {
		return m.evaluateEgress(ctx, p, srcPod, dstPod)
	}
	return VerdictNext, nil
}

func newMockEvaluator(name string, verdict Verdict, err error) *mockPolicyEvaluator {
	return &mockPolicyEvaluator{
		name: name,
		evaluateIngress: func(context.Context, *network.Packet, *api.PodInfo, *api.PodInfo) (Verdict, error) {
			return verdict, err
		},
		evaluateEgress: func(context.Context, *network.Packet, *api.PodInfo, *api.PodInfo) (Verdict, error) {
			return verdict, err
		},
	}
}

func TestPolicyEngine_EvaluatePacket(t *testing.T) {
	dummyPacket := &network.Packet{}

	tests := []struct {
		name       string
		evaluators []PolicyEvaluator
		wantAllow  bool
		wantErr    bool
	}{
		{
			name:       "empty pipeline should default to allow",
			evaluators: []PolicyEvaluator{},
			wantAllow:  true,
			wantErr:    false,
		},
		{
			name:       "single evaluator returns Accept",
			evaluators: []PolicyEvaluator{newMockEvaluator("acceptor", VerdictAccept, nil)},
			wantAllow:  true,
			wantErr:    false,
		},
		{
			name:       "single evaluator returns Deny",
			evaluators: []PolicyEvaluator{newMockEvaluator("denier", VerdictDeny, nil)},
			wantAllow:  false,
			wantErr:    false,
		},
		{
			name:       "single evaluator returns Next should default to allow",
			evaluators: []PolicyEvaluator{newMockEvaluator("passer", VerdictNext, nil)},
			wantAllow:  true,
			wantErr:    false,
		},
		{
			name: "high priority denier should run first and deny",
			evaluators: []PolicyEvaluator{
				newMockEvaluator("denier", VerdictDeny, nil),
				newMockEvaluator("acceptor", VerdictAccept, nil),
			},
			wantAllow: false,
			wantErr:   false,
		},
		{
			name: "high priority acceptor should run first and allow",
			evaluators: []PolicyEvaluator{
				newMockEvaluator("acceptor", VerdictAccept, nil),
				newMockEvaluator("denier", VerdictDeny, nil),
			},
			wantAllow: true,
			wantErr:   false,
		},
		{
			name: "evaluator returning Next should proceed to the next one",
			evaluators: []PolicyEvaluator{
				newMockEvaluator("passer", VerdictNext, nil),
				newMockEvaluator("denier", VerdictDeny, nil),
			},
			wantAllow: false,
			wantErr:   false,
		},
		{
			name: "evaluator returns an error",
			evaluators: []PolicyEvaluator{
				newMockEvaluator("error-producer", VerdictNext, errors.New("evaluation failed")),
			},
			wantAllow: false,
			wantErr:   true,
		},
		{
			name: "error from a later evaluator",
			evaluators: []PolicyEvaluator{
				newMockEvaluator("passer", VerdictNext, nil),
				newMockEvaluator("error-producer", VerdictNext, errors.New("evaluation failed")),
			},
			wantAllow: false,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := NewPolicyEngine(&FuncProvider{}, tt.evaluators)
			gotAllow, err := engine.EvaluatePacket(context.Background(), dummyPacket)

			if (err != nil) != tt.wantErr {
				t.Errorf("PolicyEngine.EvaluatePacket() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotAllow != tt.wantAllow {
				t.Errorf("PolicyEngine.EvaluatePacket() gotAllow = %v, want %v", gotAllow, tt.wantAllow)
			}
		})
	}
}

func TestPolicyEngine_EvaluatorSorting(t *testing.T) {
	var evaluationOrder []string
	e1 := &mockPolicyEvaluator{
		name: "evaluator-1",
		evaluateEgress: func(ctx context.Context, p *network.Packet, srcPod, dstPod *api.PodInfo) (Verdict, error) {
			evaluationOrder = append(evaluationOrder, "evaluator-1")
			return VerdictNext, nil
		},
	}
	e2 := &mockPolicyEvaluator{
		name: "evaluator-2",
		evaluateEgress: func(ctx context.Context, p *network.Packet, srcPod, dstPod *api.PodInfo) (Verdict, error) {
			evaluationOrder = append(evaluationOrder, "evaluator-2")
			return VerdictNext, nil
		},
	}
	e3 := &mockPolicyEvaluator{
		name: "evaluator-3",
		evaluateEgress: func(ctx context.Context, p *network.Packet, srcPod, dstPod *api.PodInfo) (Verdict, error) {
			evaluationOrder = append(evaluationOrder, "evaluator-3")
			return VerdictNext, nil
		},
	}

	engine := NewPolicyEngine(&FuncProvider{}, []PolicyEvaluator{e2, e3, e1})
	_, _ = engine.EvaluatePacket(context.Background(), &network.Packet{})

	if len(evaluationOrder) != 3 {
		t.Fatalf("expected 3 evaluators to be called, got %d", len(evaluationOrder))
	}

	// Check if they are sorted correctly by priority
	if evaluationOrder[0] != "evaluator-2" {
		t.Errorf("expected first evaluator to be 'evaluator-2', got '%s'", evaluationOrder[0])
	}
	if evaluationOrder[1] != "evaluator-3" {
		t.Errorf("expected second evaluator to be 'evaluator-3', got '%s'", evaluationOrder[1])
	}
	if evaluationOrder[2] != "evaluator-1" {
		t.Errorf("expected third evaluator to be 'evaluator-1', got '%s'", evaluationOrder[2])
	}
}

func TestPolicyEngine_EvaluatePacket_ContextCancellation(t *testing.T) {
	// This evaluator will block until the context is canceled.
	blockingEvaluator := &mockPolicyEvaluator{
		name: "blocker",
		evaluateEgress: func(ctx context.Context, p *network.Packet, srcPod, dstPod *api.PodInfo) (Verdict, error) {
			<-ctx.Done() // Wait for cancellation
			return VerdictNext, ctx.Err()
		},
	}

	engine := NewPolicyEngine(&FuncProvider{}, []PolicyEvaluator{blockingEvaluator})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := engine.EvaluatePacket(ctx, &network.Packet{})

	if err == nil {
		t.Error("expected an error due to context cancellation, but got nil")
	}

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context.DeadlineExceeded error, got %v", err)
	}
}

// --- Real Evaluator Pipeline Tests ---

// Test helpers for creating policies and cluster objects

func makeTestPod(name, namespace string, labels map[string]string, ip string) *v1.Pod {
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: labels},
		Status:     v1.PodStatus{PodIP: ip, PodIPs: []v1.PodIP{{IP: ip}}},
	}
}

func makeTestNamespace(name string, labels map[string]string) *v1.Namespace {
	return &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}
}

func makeNP(name, namespace string, podSelector labels.Set, policyTypes []networkingv1.PolicyType, egress []networkingv1.NetworkPolicyEgressRule, ingress []networkingv1.NetworkPolicyIngressRule) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: podSelector},
			PolicyTypes: policyTypes,
			Egress:      egress,
			Ingress:     ingress,
		},
	}
}

func TestSinglePipelineWithRealEvaluators(t *testing.T) {
	logs.GlogSetter("4")
	// Define common pods and namespaces for tests
	podA := makeTestPod("pod-a", "ns-a", map[string]string{"app": "a"}, "10.0.1.10")
	podB := makeTestPod("pod-b", "ns-b", map[string]string{"app": "b"}, "10.0.2.20")
	nsA := makeTestNamespace("ns-a", map[string]string{"team": "a"})
	nsB := makeTestNamespace("ns-b", map[string]string{"team": "b"})

	tests := []struct {
		name        string
		anpVerdict  Verdict // Mocked ANP verdict
		banpVerdict Verdict // Mocked BANP verdict
		nps         []*networkingv1.NetworkPolicy
		pods        []*v1.Pod
		namespaces  []*v1.Namespace
		packet      *network.Packet
		wantAllow   bool
	}{
		{
			name:        "ANP Allow overrides NP Deny",
			anpVerdict:  VerdictAccept, // ANP has high priority and allows
			banpVerdict: VerdictNext,
			nps: []*networkingv1.NetworkPolicy{
				// This NP would otherwise deny the traffic
				makeNP("deny-a-egress", "ns-a", labels.Set{"app": "a"}, []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}, nil, nil),
			},
			pods:       []*v1.Pod{podA, podB},
			namespaces: []*v1.Namespace{nsA, nsB},
			packet:     &network.Packet{SrcIP: net.ParseIP(podA.Status.PodIP), DstIP: net.ParseIP(podB.Status.PodIP), DstPort: 80, Proto: v1.ProtocolTCP},
			wantAllow:  true, // Final outcome should be Allow
		},
		{
			name:        "BANP Allow do not overrides NP Deny",
			anpVerdict:  VerdictNext,   // ANP passes decision down
			banpVerdict: VerdictAccept, // BANP allows
			nps: []*networkingv1.NetworkPolicy{
				// This NP would otherwise deny the traffic
				makeNP("deny-a-egress", "ns-a", labels.Set{"app": "a"}, []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}, nil, nil),
			},
			pods:       []*v1.Pod{podA, podB},
			namespaces: []*v1.Namespace{nsA, nsB},
			packet:     &network.Packet{SrcIP: net.ParseIP(podA.Status.PodIP), DstIP: net.ParseIP(podB.Status.PodIP), DstPort: 80, Proto: v1.ProtocolTCP},
			wantAllow:  false, // Final outcome should be Deny
		},
		{
			name:        "ANP Deny overrides NP Allow",
			anpVerdict:  VerdictDeny, // ANP has high priority and denies
			banpVerdict: VerdictNext,
			nps: []*networkingv1.NetworkPolicy{
				// This NP would otherwise allow the traffic
				makeNP("allow-a-egress", "ns-a", labels.Set{"app": "a"}, []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}, []networkingv1.NetworkPolicyEgressRule{{ /* empty egress rule allows all */ }}, nil),
			},
			pods:       []*v1.Pod{podA, podB},
			namespaces: []*v1.Namespace{nsA, nsB},
			packet:     &network.Packet{SrcIP: net.ParseIP(podA.Status.PodIP), DstIP: net.ParseIP(podB.Status.PodIP), DstPort: 80, Proto: v1.ProtocolTCP},
			wantAllow:  false, // Final outcome should be Deny
		},
		{
			name:        "NP Deny when ANP and BANP Pass",
			anpVerdict:  VerdictNext, // ANP passes decision down
			banpVerdict: VerdictNext, // BANP passes decision down
			nps: []*networkingv1.NetworkPolicy{
				// This NP selects podA and denies all egress traffic
				makeNP("deny-a-egress", "ns-a", labels.Set{"app": "a"}, []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}, nil, nil),
			},
			pods:       []*v1.Pod{podA, podB},
			namespaces: []*v1.Namespace{nsA, nsB},
			packet:     &network.Packet{SrcIP: net.ParseIP(podA.Status.PodIP), DstIP: net.ParseIP(podB.Status.PodIP), DstPort: 80, Proto: v1.ProtocolTCP},
			wantAllow:  false, // Final outcome should be Deny
		},
		{
			name:        "Default Allow when all evaluators Pass",
			anpVerdict:  VerdictNext,
			banpVerdict: VerdictNext,
			nps:         []*networkingv1.NetworkPolicy{
				// No policies select the pod, so NP evaluator should return Next
			},
			pods:       []*v1.Pod{podA, podB},
			namespaces: []*v1.Namespace{nsA, nsB},
			packet:     &network.Packet{SrcIP: net.ParseIP(podA.Status.PodIP), DstIP: net.ParseIP(podB.Status.PodIP), DstPort: 80, Proto: v1.ProtocolTCP},
			wantAllow:  true, // Pipeline default is Allow
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock informers and providers
			kubeClient := fake.NewSimpleClientset()
			informerFactory := informers.NewSharedInformerFactory(kubeClient, 0)
			netpolInformer := informerFactory.Networking().V1().NetworkPolicies()

			podInfoMap := make(map[string]*api.PodInfo)
			for _, p := range tt.pods {
				nsLabels := map[string]string{}
				for _, ns := range tt.namespaces {
					if p.Namespace == ns.Name {
						nsLabels = ns.Labels
						break
					}
				}
				podInfoMap[p.Status.PodIP] = api.NewPodInfo(p, nsLabels, nil, "")
			}

			podInfoProvider := &FuncProvider{GetFunc: func(podIP string) (*api.PodInfo, bool) {
				p, ok := podInfoMap[podIP]
				return p, ok
			}}

			// For this test, we mock the ANP/BANP evaluators to control their output,
			// but use the real NetworkPolicy evaluator.
			anpEvaluator := newMockEvaluator("AdminNetworkPolicy", tt.anpVerdict, nil)
			banpEvaluator := newMockEvaluator("BaselineAdminNetworkPolicy", tt.banpVerdict, nil)

			// Use the real NetworkPolicy evaluator, which has a default priority of 50.
			npEvaluator := NewStandardNetworkPolicy(netpolInformer)
			for _, np := range tt.nps {
				netpolInformer.Informer().GetStore().Add(np)
			}

			// A single pipeline containing all evaluators, sorted by priority.
			engine := NewPolicyEngine(podInfoProvider, []PolicyEvaluator{anpEvaluator, npEvaluator, banpEvaluator})

			allow, err := engine.EvaluatePacket(context.Background(), tt.packet)
			if err != nil {
				t.Fatalf("engine.EvaluatePacket() returned an unexpected error: %v", err)
			}

			if allow != tt.wantAllow {
				t.Errorf("Final verdict mismatch: got allow=%v, want allow=%v", allow, tt.wantAllow)
			}
		})
	}
}
