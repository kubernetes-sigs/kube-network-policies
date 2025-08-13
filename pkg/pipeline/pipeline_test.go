// SPDX-License-Identifier: APACHE-2.0

package pipeline

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"sigs.k8s.io/kube-network-policies/pkg/api"
	"sigs.k8s.io/kube-network-policies/pkg/network"
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
