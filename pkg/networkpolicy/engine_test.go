// SPDX-License-Identifier: APACHE-2.0

package networkpolicy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
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
	"k8s.io/klog/v2/textlogger"
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

// mockPolicyEvaluator is a mock implementation of PolicyEvaluator for testing.
type mockPolicyEvaluator struct {
	name            string
	evaluateIngress func(ctx context.Context, p *network.Packet, srcPod, dstPod *api.PodInfo) (api.Verdict, error)
	evaluateEgress  func(ctx context.Context, p *network.Packet, srcPod, dstPod *api.PodInfo) (api.Verdict, error)
}

func (m *mockPolicyEvaluator) Name() string {
	return m.name
}

func (m *mockPolicyEvaluator) EvaluateIngress(ctx context.Context, p *network.Packet, srcPod, dstPod *api.PodInfo) (api.Verdict, error) {
	if m.evaluateIngress != nil {
		return m.evaluateIngress(ctx, p, srcPod, dstPod)
	}
	return api.VerdictNext, nil
}

func (m *mockPolicyEvaluator) EvaluateEgress(ctx context.Context, p *network.Packet, srcPod, dstPod *api.PodInfo) (api.Verdict, error) {
	if m.evaluateEgress != nil {
		return m.evaluateEgress(ctx, p, srcPod, dstPod)
	}
	return api.VerdictNext, nil
}

func (m *mockPolicyEvaluator) Ready() bool {
	// No-op for mock, always ready.
	return true
}

func (m *mockPolicyEvaluator) SetDataplaneSyncCallback(syncFn api.SyncFunc) {
	// No-op for mock.
}

func (m *mockPolicyEvaluator) ManagedIPs(ctx context.Context) ([]netip.Addr, bool, error) {
	return nil, false, nil
}

func newMockEvaluator(name string, verdict api.Verdict, err error) *mockPolicyEvaluator {
	return &mockPolicyEvaluator{
		name: name,
		evaluateIngress: func(context.Context, *network.Packet, *api.PodInfo, *api.PodInfo) (api.Verdict, error) {
			return verdict, err
		},
		evaluateEgress: func(context.Context, *network.Packet, *api.PodInfo, *api.PodInfo) (api.Verdict, error) {
			return verdict, err
		},
	}
}

func TestPolicyEngine_EvaluatePacket(t *testing.T) {
	dummyPacket := &network.Packet{}

	tests := []struct {
		name       string
		evaluators []api.PolicyEvaluator
		wantAllow  bool
		wantErr    bool
	}{
		{
			name:       "empty pipeline should default to allow",
			evaluators: []api.PolicyEvaluator{},
			wantAllow:  true,
			wantErr:    false,
		},
		{
			name:       "single evaluator returns Accept",
			evaluators: []api.PolicyEvaluator{newMockEvaluator("acceptor", api.VerdictAccept, nil)},
			wantAllow:  true,
			wantErr:    false,
		},
		{
			name:       "single evaluator returns Deny",
			evaluators: []api.PolicyEvaluator{newMockEvaluator("denier", api.VerdictDeny, nil)},
			wantAllow:  false,
			wantErr:    false,
		},
		{
			name:       "single evaluator returns Next should default to allow",
			evaluators: []api.PolicyEvaluator{newMockEvaluator("passer", api.VerdictNext, nil)},
			wantAllow:  true,
			wantErr:    false,
		},
		{
			name: "high priority denier should run first and deny",
			evaluators: []api.PolicyEvaluator{
				newMockEvaluator("denier", api.VerdictDeny, nil),
				newMockEvaluator("acceptor", api.VerdictAccept, nil),
			},
			wantAllow: false,
			wantErr:   false,
		},
		{
			name: "high priority acceptor should run first and allow",
			evaluators: []api.PolicyEvaluator{
				newMockEvaluator("acceptor", api.VerdictAccept, nil),
				newMockEvaluator("denier", api.VerdictDeny, nil),
			},
			wantAllow: true,
			wantErr:   false,
		},
		{
			name: "evaluator returning Next should proceed to the next one",
			evaluators: []api.PolicyEvaluator{
				newMockEvaluator("passer", api.VerdictNext, nil),
				newMockEvaluator("denier", api.VerdictDeny, nil),
			},
			wantAllow: false,
			wantErr:   false,
		},
		{
			name: "evaluator returns an error",
			evaluators: []api.PolicyEvaluator{
				newMockEvaluator("error-producer", api.VerdictNext, errors.New("evaluation failed")),
			},
			wantAllow: false,
			wantErr:   true,
		},
		{
			name: "error from a later evaluator",
			evaluators: []api.PolicyEvaluator{
				newMockEvaluator("passer", api.VerdictNext, nil),
				newMockEvaluator("error-producer", api.VerdictNext, errors.New("evaluation failed")),
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
		evaluateEgress: func(ctx context.Context, p *network.Packet, srcPod, dstPod *api.PodInfo) (api.Verdict, error) {
			evaluationOrder = append(evaluationOrder, "evaluator-1")
			return api.VerdictNext, nil
		},
	}
	e2 := &mockPolicyEvaluator{
		name: "evaluator-2",
		evaluateEgress: func(ctx context.Context, p *network.Packet, srcPod, dstPod *api.PodInfo) (api.Verdict, error) {
			evaluationOrder = append(evaluationOrder, "evaluator-2")
			return api.VerdictNext, nil
		},
	}
	e3 := &mockPolicyEvaluator{
		name: "evaluator-3",
		evaluateEgress: func(ctx context.Context, p *network.Packet, srcPod, dstPod *api.PodInfo) (api.Verdict, error) {
			evaluationOrder = append(evaluationOrder, "evaluator-3")
			return api.VerdictNext, nil
		},
	}

	engine := NewPolicyEngine(&FuncProvider{}, []api.PolicyEvaluator{e2, e3, e1})
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
		evaluateEgress: func(ctx context.Context, p *network.Packet, srcPod, dstPod *api.PodInfo) (api.Verdict, error) {
			<-ctx.Done() // Wait for cancellation
			return api.VerdictNext, ctx.Err()
		},
	}

	engine := NewPolicyEngine(&FuncProvider{}, []api.PolicyEvaluator{blockingEvaluator})

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

// newDirectionalMockEvaluator returns an evaluator with a different verdict
// per direction.
func newDirectionalMockEvaluator(name string, egress, ingress api.Verdict) *mockPolicyEvaluator {
	return &mockPolicyEvaluator{
		name: name,
		evaluateEgress: func(context.Context, *network.Packet, *api.PodInfo, *api.PodInfo) (api.Verdict, error) {
			return egress, nil
		},
		evaluateIngress: func(context.Context, *network.Packet, *api.PodInfo, *api.PodInfo) (api.Verdict, error) {
			return ingress, nil
		},
	}
}

func TestPolicyEngine_LogVerdict(t *testing.T) {
	srcPod := &api.PodInfo{Name: "client", Namespace: &api.Namespace{Name: "default"}}
	dstPod := &api.PodInfo{Name: "web", Namespace: &api.Namespace{Name: "default"}}
	podInfoProvider := &FuncProvider{GetFunc: func(podIP string) (*api.PodInfo, bool) {
		switch podIP {
		case "10.0.0.1":
			return srcPod, true
		case "10.0.0.2":
			return dstPod, true
		}
		return nil, false
	}}
	packet := &network.Packet{
		ID:      42,
		Family:  v1.IPv4Protocol,
		SrcIP:   net.ParseIP("10.0.0.1"),
		DstIP:   net.ParseIP("10.0.0.2"),
		Proto:   v1.ProtocolTCP,
		SrcPort: 12345,
		DstPort: 80,
		Payload: []byte{0xde, 0xad},
	}
	// want is the packet the record must describe, whatever the caller does
	// with its packet after the verdict.
	want := *packet

	tests := []struct {
		name       string
		mode       VerdictLogMode
		evaluators []api.PolicyEvaluator
		// wantRecord is nil when no record must be logged
		wantRecord *verdictRecord
	}{
		{
			name: "denied by the first evaluator at egress",
			mode: VerdictLogDeny,
			evaluators: []api.PolicyEvaluator{
				newDirectionalMockEvaluator("admin", api.VerdictDeny, api.VerdictNext),
				newDirectionalMockEvaluator("baseline", api.VerdictNext, api.VerdictNext),
			},
			wantRecord: &verdictRecord{verdict: api.VerdictDeny, direction: DirectionEgress, evaluator: "admin"},
		},
		{
			name: "denied by the second evaluator at ingress",
			mode: VerdictLogDeny,
			evaluators: []api.PolicyEvaluator{
				newDirectionalMockEvaluator("admin", api.VerdictNext, api.VerdictNext),
				newDirectionalMockEvaluator("baseline", api.VerdictNext, api.VerdictDeny),
			},
			wantRecord: &verdictRecord{verdict: api.VerdictDeny, direction: DirectionIngress, evaluator: "baseline"},
		},
		{
			name: "egress accept does not skip the ingress denial",
			mode: VerdictLogDeny,
			evaluators: []api.PolicyEvaluator{
				newDirectionalMockEvaluator("admin", api.VerdictAccept, api.VerdictDeny),
			},
			wantRecord: &verdictRecord{verdict: api.VerdictDeny, direction: DirectionIngress, evaluator: "admin"},
		},
		{
			name: "accepted by an evaluator at ingress",
			mode: VerdictLogAll,
			evaluators: []api.PolicyEvaluator{
				newDirectionalMockEvaluator("admin", api.VerdictNext, api.VerdictAccept),
			},
			wantRecord: &verdictRecord{verdict: api.VerdictAccept, direction: DirectionIngress, evaluator: "admin"},
		},
		{
			name: "accepted by default",
			mode: VerdictLogAll,
			evaluators: []api.PolicyEvaluator{
				newDirectionalMockEvaluator("admin", api.VerdictNext, api.VerdictNext),
			},
			wantRecord: &verdictRecord{verdict: api.VerdictAccept},
		},
		{
			name: "accepted packets are not logged in deny mode",
			mode: VerdictLogDeny,
			evaluators: []api.PolicyEvaluator{
				newDirectionalMockEvaluator("admin", api.VerdictAccept, api.VerdictAccept),
			},
		},
		{
			name: "evaluation errors are not verdicts",
			mode: VerdictLogAll,
			evaluators: []api.PolicyEvaluator{
				newMockEvaluator("broken", api.VerdictNext, errors.New("evaluation failed")),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := NewPolicyEngine(podInfoProvider, tt.evaluators)
			verdictLogger := newVerdictLogger(textlogger.NewLogger(textlogger.NewConfig()), tt.mode, 1)
			engine.SetVerdictLogger(verdictLogger)

			allowed, err := engine.EvaluatePacket(context.Background(), packet)
			if tt.wantRecord != nil && (err != nil || allowed != (tt.wantRecord.verdict == api.VerdictAccept)) {
				t.Fatalf("EvaluatePacket() = %v, %v, want %v", allowed, err, tt.wantRecord.verdict == api.VerdictAccept)
			}
			// The caller owns the packet, the record must not change with it.
			packet.SrcIP, packet.DstIP = packet.DstIP, packet.SrcIP
			packet.SrcPort, packet.DstPort = packet.DstPort, packet.SrcPort
			defer func() {
				packet.SrcIP, packet.DstIP = packet.DstIP, packet.SrcIP
				packet.SrcPort, packet.DstPort = packet.DstPort, packet.SrcPort
			}()

			var got *verdictRecord
			select {
			case r := <-verdictLogger.records:
				got = &r
			default:
			}
			if tt.wantRecord == nil {
				if got != nil {
					t.Fatalf("unexpected record %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("expected a record")
			}
			if got.verdict != tt.wantRecord.verdict || got.direction != tt.wantRecord.direction || got.evaluator != tt.wantRecord.evaluator {
				t.Errorf("record verdict = (%v, %q, %q), want (%v, %q, %q)",
					got.verdict, got.direction, got.evaluator,
					tt.wantRecord.verdict, tt.wantRecord.direction, tt.wantRecord.evaluator)
			}
			if got.srcPod != srcPod || got.dstPod != dstPod {
				t.Errorf("record pods = (%v, %v), want the pods resolved for the packet", got.srcPod, got.dstPod)
			}
			wantSrc := netip.MustParseAddrPort(net.JoinHostPort(want.SrcIP.String(), strconv.Itoa(want.SrcPort)))
			wantDst := netip.MustParseAddrPort(net.JoinHostPort(want.DstIP.String(), strconv.Itoa(want.DstPort)))
			if got.id != want.ID || got.family != want.Family || got.proto != want.Proto || got.src != wantSrc || got.dst != wantDst {
				t.Errorf("record packet = %+v, want %+v", *got, want)
			}
		})
	}
}

func TestPolicyEngine_EvaluatePacket_WithoutVerdictLogger(t *testing.T) {
	engine := NewPolicyEngine(&FuncProvider{}, []api.PolicyEvaluator{newMockEvaluator("denier", api.VerdictDeny, nil)})
	allowed, err := engine.EvaluatePacket(context.Background(), &network.Packet{})
	if err != nil || allowed {
		t.Fatalf("EvaluatePacket() = %v, %v, want false, nil", allowed, err)
	}
}

// stuckWriter is a log destination that stops accepting writes, as the
// stderr of a container does when the runtime stops reading it. The first
// Write blocks until release is closed and signals it through blocked.
type stuckWriter struct {
	once    sync.Once
	blocked chan struct{}
	release chan struct{}
}

func (w *stuckWriter) Write(p []byte) (int, error) {
	w.once.Do(func() {
		close(w.blocked)
		<-w.release
	})
	return len(p), nil
}

// The nfqueue callback that calls EvaluatePacket runs sequentially, so a
// verdict that waits for the log destination delays every queued packet.
// With the destination stuck, the evaluation must keep going and the verdicts
// that do not fit in the buffer must be dropped.
func TestPolicyEngine_EvaluatePacket_DoesNotBlockOnVerdictLog(t *testing.T) {
	writer := &stuckWriter{blocked: make(chan struct{}), release: make(chan struct{})}
	logger := textlogger.NewLogger(textlogger.NewConfig(textlogger.Output(writer)))
	const bufferSize = 8
	verdictLogger := newVerdictLogger(logger, VerdictLogDeny, bufferSize)
	engine := NewPolicyEngine(&FuncProvider{}, []api.PolicyEvaluator{newMockEvaluator("denier", api.VerdictDeny, nil)})
	engine.SetVerdictLogger(verdictLogger)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		verdictLogger.Run(ctx)
	}()
	defer func() {
		cancel()
		<-done
	}()

	packet := &network.Packet{SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("10.0.0.2")}
	// The logger takes the first verdict and its write gets stuck.
	if allowed, err := engine.EvaluatePacket(context.Background(), packet); err != nil || allowed {
		t.Fatalf("EvaluatePacket() = %v, %v, want false, nil", allowed, err)
	}
	select {
	case <-writer.blocked:
	case <-time.After(5 * time.Second):
		t.Fatal("the verdict logger did not write the first verdict")
	}
	droppedBefore := verdictLogDroppedValue(t)

	// The next verdicts fill the buffer and the rest are dropped, none of
	// them waits for the destination.
	const extra = 5
	var evalErr error
	evaluated := make(chan struct{})
	go func() {
		defer close(evaluated)
		for i := 0; i < bufferSize+extra; i++ {
			allowed, err := engine.EvaluatePacket(context.Background(), packet)
			if err != nil || allowed {
				evalErr = fmt.Errorf("EvaluatePacket() = %v, %v, want false, nil", allowed, err)
				return
			}
		}
	}()
	select {
	case <-evaluated:
	case <-time.After(5 * time.Second):
		t.Fatal("EvaluatePacket blocked on the verdict log")
	}
	if evalErr != nil {
		t.Fatal(evalErr)
	}
	if got := verdictLogDroppedValue(t) - droppedBefore; got != extra {
		t.Errorf("dropped verdicts = %v, want %d", got, extra)
	}

	// Once the destination accepts writes again the buffered verdicts are
	// written.
	close(writer.release)
	cancel()
	<-done
	if got := len(verdictLogger.records); got != 0 {
		t.Errorf("%d verdicts left in the buffer after Run returned", got)
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
		anpVerdict  api.Verdict // Mocked ANP verdict
		banpVerdict api.Verdict // Mocked BANP verdict
		nps         []*networkingv1.NetworkPolicy
		pods        []*v1.Pod
		namespaces  []*v1.Namespace
		packet      *network.Packet
		wantAllow   bool
	}{
		{
			name:        "ANP Allow overrides NP Deny",
			anpVerdict:  api.VerdictAccept, // ANP has high priority and allows
			banpVerdict: api.VerdictNext,
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
			anpVerdict:  api.VerdictNext,   // ANP passes decision down
			banpVerdict: api.VerdictAccept, // BANP allows
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
			anpVerdict:  api.VerdictDeny, // ANP has high priority and denies
			banpVerdict: api.VerdictNext,
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
			anpVerdict:  api.VerdictNext, // ANP passes decision down
			banpVerdict: api.VerdictNext, // BANP passes decision down
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
			name:        "NP Allow when ANP Pass and BANP Deny",
			anpVerdict:  api.VerdictNext, // ANP passes decision down
			banpVerdict: api.VerdictDeny, // BANP passes decision down
			nps: []*networkingv1.NetworkPolicy{
				// This NP selects podA and denies all egress traffic
				makeNP("allow-a-egress", "ns-a", labels.Set{"app": "a"}, []networkingv1.PolicyType{networkingv1.PolicyTypeEgress, networkingv1.PolicyTypeIngress}, []networkingv1.NetworkPolicyEgressRule{{ /* empty egress rule allows all */ }}, nil),
				makeNP("allow-b-ingress", "ns-b", labels.Set{"app": "b"}, []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}, nil, []networkingv1.NetworkPolicyIngressRule{{ /* empty egress rule allows all */ }}),
			},
			pods:       []*v1.Pod{podA, podB},
			namespaces: []*v1.Namespace{nsA, nsB},
			packet:     &network.Packet{SrcIP: net.ParseIP(podA.Status.PodIP), DstIP: net.ParseIP(podB.Status.PodIP), DstPort: 80, Proto: v1.ProtocolTCP},
			wantAllow:  true, // Final outcome should be Accept
		},
		{
			name:        "Default Allow when all evaluators Pass",
			anpVerdict:  api.VerdictNext,
			banpVerdict: api.VerdictNext,
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
			namespaceInformer := informerFactory.Core().V1().Namespaces()
			podInformer := informerFactory.Core().V1().Pods()

			// Start informers
			informerFactory.Start(context.Background().Done())

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
			npEvaluator := NewStandardNetworkPolicy("test", namespaceInformer, podInformer, netpolInformer)
			for _, np := range tt.nps {
				netpolInformer.Informer().GetStore().Add(np)
			}

			// A single pipeline containing all evaluators, sorted by priority.
			engine := NewPolicyEngine(podInfoProvider, []api.PolicyEvaluator{anpEvaluator, npEvaluator, banpEvaluator})

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
