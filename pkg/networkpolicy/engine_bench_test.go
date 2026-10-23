// SPDX-License-Identifier: APACHE-2.0

package networkpolicy

import (
	"context"
	"io"
	"os"
	"testing"

	"k8s.io/klog/v2"
	"k8s.io/klog/v2/textlogger"

	"sigs.k8s.io/kube-network-policies/pkg/api"
	"sigs.k8s.io/kube-network-policies/pkg/network"
)

// tcpSYN is the first packet of a TCP connection from 192.168.1.201:46818 to
// 192.168.1.1:5001, the packet the dataplane queues for every new connection.
var tcpSYN = []byte{
	0x45, 0x00, 0x00, 0x3c, 0x83, 0x11, 0x40, 0x00, 0x40, 0x06, 0x33, 0x90, 0xc0, 0xa8, 0x01, 0xc9,
	0xc0, 0xa8, 0x01, 0x01, 0xb6, 0xe2, 0x13, 0x89, 0x7f, 0x41, 0x17, 0x6c, 0x00, 0x00, 0x00, 0x00,
	0xa0, 0x02, 0xfa, 0xf0, 0x84, 0x49, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a,
	0x12, 0x20, 0x68, 0xba, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x06,
}

// newTracingEvaluator returns an evaluator that, like the production ones,
// writes one V(2) line per direction with the result of its evaluation.
func newTracingEvaluator(name string, egress, ingress api.Verdict) *mockPolicyEvaluator {
	return &mockPolicyEvaluator{
		name: name,
		evaluateEgress: func(ctx context.Context, p *network.Packet, srcPod, dstPod *api.PodInfo) (api.Verdict, error) {
			klog.FromContext(ctx).V(2).Info("Egress evaluation", "evaluator", name, "npolicies", 1, "action", "Pass")
			return egress, nil
		},
		evaluateIngress: func(ctx context.Context, p *network.Packet, srcPod, dstPod *api.PodInfo) (api.Verdict, error) {
			klog.FromContext(ctx).V(2).Info("Ingress evaluation", "evaluator", name, "npolicies", 1, "action", "Pass")
			return ingress, nil
		},
	}
}

// benchPodInfoProvider resolves both ends of tcpSYN to a Pod.
func benchPodInfoProvider() api.PodInfoProvider {
	client := &api.PodInfo{Name: "client", Namespace: &api.Namespace{Name: "default"}}
	web := &api.PodInfo{Name: "web", Namespace: &api.Namespace{Name: "default"}}
	return &FuncProvider{GetFunc: func(podIP string) (*api.PodInfo, bool) {
		if podIP == "192.168.1.201" {
			return client, true
		}
		return web, true
	}}
}

// benchSink returns the writer the log lines go to. A pipe drained by another
// goroutine is the closest to the stderr of a container, every line is a
// write system call.
func benchSink(b *testing.B, name string) io.Writer {
	switch name {
	case "discard":
		return io.Discard
	case "pipe":
		r, w, err := os.Pipe()
		if err != nil {
			b.Fatal(err)
		}
		go io.Copy(io.Discard, r) //nolint:errcheck
		b.Cleanup(func() {
			w.Close()
			r.Close()
		})
		return w
	default:
		b.Fatalf("unknown sink %q", name)
		return nil
	}
}

// BenchmarkEvaluatePacket measures the verdict of one packet through a
// pipeline with the shape of the npa-v1alpha2 binary: an admin tier, the
// standard NetworkPolicy and a baseline tier. At verbosity 2 the pipeline is
// preceded by the LoggingPolicy, as in the binaries, and every component
// writes its per-packet trace. The verdict log cases run at verbosity 0 with
// the verdicts written by the VerdictLogger, the records it drops because
// the writer does not keep up with the loop are reported as dropped/op.
func BenchmarkEvaluatePacket(b *testing.B) {
	cases := []struct {
		name      string
		verbosity int
		sink      string
		// verdictLog is the mode of the VerdictLogger, empty to not log verdicts
		verdictLog VerdictLogMode
		// ingress verdict of the baseline tier, the last evaluator
		baseline api.Verdict
	}{
		{name: "accept/v0", verbosity: 0, sink: "discard", baseline: api.VerdictNext},
		{name: "accept/v2/discard", verbosity: 2, sink: "discard", baseline: api.VerdictNext},
		{name: "accept/v2/pipe", verbosity: 2, sink: "pipe", baseline: api.VerdictNext},
		{name: "accept/v0/verdictlog=deny/pipe", verbosity: 0, sink: "pipe", verdictLog: VerdictLogDeny, baseline: api.VerdictNext},
		{name: "accept/v0/verdictlog=all/pipe", verbosity: 0, sink: "pipe", verdictLog: VerdictLogAll, baseline: api.VerdictNext},
		{name: "deny/v0", verbosity: 0, sink: "discard", baseline: api.VerdictDeny},
		{name: "deny/v2/discard", verbosity: 2, sink: "discard", baseline: api.VerdictDeny},
		{name: "deny/v2/pipe", verbosity: 2, sink: "pipe", baseline: api.VerdictDeny},
		{name: "deny/v0/verdictlog=deny/pipe", verbosity: 0, sink: "pipe", verdictLog: VerdictLogDeny, baseline: api.VerdictDeny},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			packet, err := network.ParsePacket(tcpSYN)
			if err != nil {
				b.Fatal(err)
			}
			packet.ID = 1

			evaluators := []api.PolicyEvaluator{}
			if tc.verbosity >= 2 {
				evaluators = append(evaluators, NewLoggingPolicy())
			}
			evaluators = append(evaluators,
				newTracingEvaluator("ClusterNetworkPolicyAdmin", api.VerdictNext, api.VerdictNext),
				newTracingEvaluator("StandardNetworkPolicy", api.VerdictNext, api.VerdictNext),
				newTracingEvaluator("ClusterNetworkPolicyBaseline", api.VerdictNext, tc.baseline),
			)
			engine := NewPolicyEngine(benchPodInfoProvider(), evaluators)

			logger := textlogger.NewLogger(textlogger.NewConfig(
				textlogger.Verbosity(tc.verbosity),
				textlogger.Output(benchSink(b, tc.sink)),
			))
			ctx := klog.NewContext(context.Background(), logger)

			var droppedBefore float64
			if tc.verdictLog != "" {
				verdictLogger := NewVerdictLogger(logger, tc.verdictLog)
				engine.SetVerdictLogger(verdictLogger)
				droppedBefore = verdictLogDroppedValue(b)
				ctx, cancel := context.WithCancel(ctx)
				done := make(chan struct{})
				go func() {
					defer close(done)
					verdictLogger.Run(ctx)
				}()
				b.Cleanup(func() {
					cancel()
					<-done
				})
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				allowed, err := engine.EvaluatePacket(ctx, &packet)
				if err != nil {
					b.Fatal(err)
				}
				if allowed != (tc.baseline != api.VerdictDeny) {
					b.Fatalf("unexpected verdict %v", allowed)
				}
			}
			b.StopTimer()
			if tc.verdictLog != "" {
				b.ReportMetric((verdictLogDroppedValue(b)-droppedBefore)/float64(b.N), "dropped/op")
			}
		})
	}
}
