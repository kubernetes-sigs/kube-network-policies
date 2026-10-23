// SPDX-License-Identifier: APACHE-2.0

package networkpolicy

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2/textlogger"

	"sigs.k8s.io/kube-network-policies/pkg/api"
	"sigs.k8s.io/kube-network-policies/pkg/network"
)

func TestVerdictLogMode_Set(t *testing.T) {
	tests := []struct {
		value   string
		want    VerdictLogMode
		wantErr bool
	}{
		{value: "none", want: VerdictLogNone},
		{value: "deny", want: VerdictLogDeny},
		{value: "all", want: VerdictLogAll},
		{value: "", wantErr: true},
		{value: "Deny", wantErr: true},
		{value: "accept", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			var mode VerdictLogMode
			err := mode.Set(tt.value)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Set(%q) error = %v, wantErr %v", tt.value, err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if mode != tt.want {
				t.Errorf("Set(%q) = %q, want %q", tt.value, mode, tt.want)
			}
			if mode.String() != tt.value {
				t.Errorf("String() = %q, want %q", mode.String(), tt.value)
			}
		})
	}
}

func TestVerdictLogMode_logs(t *testing.T) {
	tests := []struct {
		mode    VerdictLogMode
		verdict api.Verdict
		want    bool
	}{
		{mode: VerdictLogNone, verdict: api.VerdictDeny, want: false},
		{mode: VerdictLogNone, verdict: api.VerdictAccept, want: false},
		{mode: VerdictLogDeny, verdict: api.VerdictDeny, want: true},
		{mode: VerdictLogDeny, verdict: api.VerdictAccept, want: false},
		{mode: VerdictLogAll, verdict: api.VerdictDeny, want: true},
		{mode: VerdictLogAll, verdict: api.VerdictAccept, want: true},
	}
	for _, tt := range tests {
		if got := tt.mode.logs(tt.verdict); got != tt.want {
			t.Errorf("%q.logs(%v) = %v, want %v", tt.mode, tt.verdict, got, tt.want)
		}
	}
}

// testVerdictRecord is the denial of a TCP connection from a Pod to an
// external IP.
func testVerdictRecord(verdict api.Verdict) VerdictRecord {
	return VerdictRecord{
		Packet: network.Packet{
			ID:      7,
			Family:  v1.IPv4Protocol,
			SrcIP:   net.ParseIP("192.168.1.201"),
			DstIP:   net.ParseIP("192.168.1.1"),
			Proto:   v1.ProtocolTCP,
			SrcPort: 46818,
			DstPort: 5001,
			Payload: []byte{0x01, 0x02},
		},
		SrcPod:    &api.PodInfo{Name: "client", Namespace: &api.Namespace{Name: "default"}},
		Verdict:   verdict,
		Direction: DirectionIngress,
		Evaluator: "StandardNetworkPolicy",
	}
}

func TestVerdictLogger_Log(t *testing.T) {
	tests := []struct {
		name    string
		mode    VerdictLogMode
		verdict api.Verdict
		want    bool
	}{
		{name: "deny mode buffers denials", mode: VerdictLogDeny, verdict: api.VerdictDeny, want: true},
		{name: "deny mode ignores accepts", mode: VerdictLogDeny, verdict: api.VerdictAccept, want: false},
		{name: "all mode buffers accepts", mode: VerdictLogAll, verdict: api.VerdictAccept, want: true},
		{name: "none mode ignores denials", mode: VerdictLogNone, verdict: api.VerdictDeny, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := newVerdictLogger(textlogger.NewLogger(textlogger.NewConfig()), tt.mode, 1)
			l.Log(testVerdictRecord(tt.verdict))
			select {
			case r := <-l.records:
				if !tt.want {
					t.Fatalf("unexpected record %+v", r)
				}
				if r.Packet.Payload != nil {
					t.Errorf("the payload must not be kept, got %v", r.Packet.Payload)
				}
			default:
				if tt.want {
					t.Fatal("expected a record")
				}
			}
		})
	}
}

func TestVerdictLogger_LogDoesNotBlock(t *testing.T) {
	l := newVerdictLogger(textlogger.NewLogger(textlogger.NewConfig()), VerdictLogDeny, 2)
	droppedBefore := verdictLogDroppedValue(t)
	// Nobody is running the logger, the third record does not fit.
	for i := 0; i < 3; i++ {
		l.Log(testVerdictRecord(api.VerdictDeny))
	}
	if got := len(l.records); got != 2 {
		t.Errorf("buffered records = %d, want 2", got)
	}
	if got := verdictLogDroppedValue(t) - droppedBefore; got != 1 {
		t.Errorf("dropped records = %v, want 1", got)
	}
}

// verdictLogDroppedValue returns the value of the registered
// kube_network_policies_verdict_log_dropped metric.
func verdictLogDroppedValue(tb testing.TB) float64 {
	tb.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		tb.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() == "kube_network_policies_verdict_log_dropped" {
			return family.GetMetric()[0].GetCounter().GetValue()
		}
	}
	tb.Fatal("metric kube_network_policies_verdict_log_dropped is not registered")
	return 0
}

func TestVerdictLogger_Run(t *testing.T) {
	var buf bytes.Buffer
	logger := textlogger.NewLogger(textlogger.NewConfig(textlogger.Output(&buf)))
	l := newVerdictLogger(logger, VerdictLogAll, 8)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		l.Run(ctx)
	}()

	l.Log(testVerdictRecord(api.VerdictDeny))
	accepted := testVerdictRecord(api.VerdictAccept)
	accepted.Direction = ""
	accepted.Evaluator = ""
	l.Log(accepted)
	cancel()
	<-done

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 log lines, got %d:\n%s", len(lines), buf.String())
	}
	for _, want := range []string{
		`"Packet verdict"`,
		`id=7`,
		`verdict="deny"`,
		`family="IPv4"`,
		`protocol="TCP"`,
		`src="192.168.1.201:46818"`,
		`dst="192.168.1.1:5001"`,
		`srcPod="default/client"`,
		`dstPod="external"`,
		`direction="ingress"`,
		`evaluator="StandardNetworkPolicy"`,
	} {
		if !strings.Contains(lines[0], want) {
			t.Errorf("denied line does not contain %s:\n%s", want, lines[0])
		}
	}
	for _, want := range []string{`"Packet verdict"`, `verdict="accept"`, `direction=""`, `evaluator=""`} {
		if !strings.Contains(lines[1], want) {
			t.Errorf("accepted line does not contain %s:\n%s", want, lines[1])
		}
	}
}

func TestVerdictLogger_RunWritesBufferedRecordsOnShutdown(t *testing.T) {
	var buf bytes.Buffer
	logger := textlogger.NewLogger(textlogger.NewConfig(textlogger.Output(&buf)))
	l := newVerdictLogger(logger, VerdictLogDeny, 8)
	for i := 0; i < 3; i++ {
		l.Log(testVerdictRecord(api.VerdictDeny))
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	l.Run(ctx)

	if got := strings.Count(buf.String(), `verdict="deny"`); got != 3 {
		t.Errorf("expected the 3 buffered records to be written, got %d:\n%s", got, buf.String())
	}
}
