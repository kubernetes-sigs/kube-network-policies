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

// mockEvaluator is a helper to create an Evaluator for testing purposes.
func mockEvaluator(name string, priority int, verdict Verdict, err error) Evaluator {
	return Evaluator{
		Name:     name,
		Priority: priority,
		Evaluate: func(ctx context.Context, p *network.Packet) (Verdict, error) {
			return verdict, err
		},
	}
}

func TestPipeline_Run(t *testing.T) {
	dummyPacket := &network.Packet{}

	tests := []struct {
		name       string
		evaluators []Evaluator
		wantAllow  bool
		wantErr    bool
	}{
		{
			name:       "empty pipeline should default to allow",
			evaluators: []Evaluator{},
			wantAllow:  true,
			wantErr:    false,
		},
		{
			name:       "single evaluator returns Accept",
			evaluators: []Evaluator{mockEvaluator("acceptor", 10, VerdictAccept, nil)},
			wantAllow:  true,
			wantErr:    false,
		},
		{
			name:       "single evaluator returns Deny",
			evaluators: []Evaluator{mockEvaluator("denier", 10, VerdictDeny, nil)},
			wantAllow:  false,
			wantErr:    false,
		},
		{
			name:       "single evaluator returns Next should default to allow",
			evaluators: []Evaluator{mockEvaluator("passer", 10, VerdictNext, nil)},
			wantAllow:  true,
			wantErr:    false,
		},
		{
			name: "high priority denier should run first and deny",
			evaluators: []Evaluator{
				mockEvaluator("acceptor", 20, VerdictAccept, nil),
				mockEvaluator("denier", 10, VerdictDeny, nil),
			},
			wantAllow: false,
			wantErr:   false,
		},
		{
			name: "high priority acceptor should run first and allow",
			evaluators: []Evaluator{
				mockEvaluator("denier", 20, VerdictDeny, nil),
				mockEvaluator("acceptor", 10, VerdictAccept, nil),
			},
			wantAllow: true,
			wantErr:   false,
		},
		{
			name: "evaluator returning Next should proceed to the next one",
			evaluators: []Evaluator{
				mockEvaluator("passer", 10, VerdictNext, nil),
				mockEvaluator("denier", 20, VerdictDeny, nil),
			},
			wantAllow: false,
			wantErr:   false,
		},
		{
			name: "evaluator returns an error",
			evaluators: []Evaluator{
				mockEvaluator("error-producer", 10, VerdictNext, errors.New("evaluation failed")),
			},
			wantAllow: false,
			wantErr:   true,
		},
		{
			name: "error from a later evaluator",
			evaluators: []Evaluator{
				mockEvaluator("passer", 10, VerdictNext, nil),
				mockEvaluator("error-producer", 20, VerdictNext, errors.New("evaluation failed")),
			},
			wantAllow: false,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pipeline := NewPipeline(tt.evaluators...)
			gotAllow, err := pipeline.Run(context.Background(), dummyPacket)

			if (err != nil) != tt.wantErr {
				t.Errorf("Pipeline.Run() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotAllow != tt.wantAllow {
				t.Errorf("Pipeline.Run() gotAllow = %v, want %v", gotAllow, tt.wantAllow)
			}
		})
	}
}

func TestPipeline_AddEvaluator(t *testing.T) {
	p := NewPipeline()
	e1 := mockEvaluator("evaluator-1", 20, VerdictNext, nil)
	e2 := mockEvaluator("evaluator-2", 10, VerdictNext, nil)
	e3 := mockEvaluator("evaluator-3", 15, VerdictNext, nil)

	p.AddEvaluator(e1)
	p.AddEvaluator(e2)
	p.AddEvaluator(e3)

	if len(p.evaluators) != 3 {
		t.Fatalf("expected 3 evaluators, got %d", len(p.evaluators))
	}

	// Check if they are sorted correctly by priority
	if p.evaluators[0].Name != "evaluator-2" {
		t.Errorf("expected first evaluator to be 'evaluator-2', got '%s'", p.evaluators[0].Name)
	}
	if p.evaluators[1].Name != "evaluator-3" {
		t.Errorf("expected second evaluator to be 'evaluator-3', got '%s'", p.evaluators[1].Name)
	}
	if p.evaluators[2].Name != "evaluator-1" {
		t.Errorf("expected third evaluator to be 'evaluator-1', got '%s'", p.evaluators[2].Name)
	}
}

func TestPipeline_Run_ContextCancellation(t *testing.T) {
	// This evaluator will block until the context is canceled.
	blockingEvaluator := Evaluator{
		Name:     "blocker",
		Priority: 10,
		Evaluate: func(ctx context.Context, p *network.Packet) (Verdict, error) {
			<-ctx.Done() // Wait for cancellation
			return VerdictNext, ctx.Err()
		},
	}

	pipeline := NewPipeline(blockingEvaluator)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := pipeline.Run(ctx, &network.Packet{})

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
			anpEvaluator := mockEvaluator("AdminNetworkPolicy", 10, tt.anpVerdict, nil)
			banpEvaluator := mockEvaluator("BaselineAdminNetworkPolicy", 100, tt.banpVerdict, nil)

			// Use the real NetworkPolicy evaluator, which has a default priority of 50.
			npEvaluator := NewNetworkPolicyEvaluator("test-node", podInfoProvider, netpolInformer)
			for _, np := range tt.nps {
				netpolInformer.Informer().GetStore().Add(np)
			}

			// A single pipeline containing all evaluators, sorted by priority.
			pipeline := NewPipeline(anpEvaluator, banpEvaluator, npEvaluator)

			allow, err := pipeline.Run(context.Background(), tt.packet)
			if err != nil {
				t.Fatalf("pipeline.Run() returned an unexpected error: %v", err)
			}

			if allow != tt.wantAllow {
				t.Errorf("Final verdict mismatch: got allow=%v, want allow=%v", allow, tt.wantAllow)
			}
		})
	}
}
