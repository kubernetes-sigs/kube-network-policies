// SPDX-License-Identifier: APACHE-2.0

package networkpolicy

import (
	"context"

	"k8s.io/klog/v2"
	"sigs.k8s.io/kube-network-policies/pkg/api"
	"sigs.k8s.io/kube-network-policies/pkg/network"
)

// LoggingPolicy implements the PolicyEvaluator interface to log packet details.
// It is intended to be the first evaluator in the engine to provide visibility.
type LoggingPolicy struct{}

// NewLoggingPolicy creates a new logging policy evaluator.
func NewLoggingPolicy() *LoggingPolicy {
	return &LoggingPolicy{}
}

// Name returns the name of the policy evaluator.
func (l *LoggingPolicy) Name() string {
	return "LoggingPolicy"
}

// EvaluateIngress logs the details of an ingress packet and passes it to the next evaluator.
func (l *LoggingPolicy) EvaluateIngress(ctx context.Context, p *network.Packet, srcPod, dstPod *api.PodInfo) (Verdict, error) {
	logPacket(ctx, "Ingress", p, srcPod, dstPod)
	return VerdictNext, nil
}

// EvaluateEgress logs the details of an egress packet and passes it to the next evaluator.
func (l *LoggingPolicy) EvaluateEgress(ctx context.Context, p *network.Packet, srcPod, dstPod *api.PodInfo) (Verdict, error) {
	logPacket(ctx, "Egress", p, srcPod, dstPod)
	return VerdictNext, nil
}

// logPacket is a helper function to format and write the log message.
func logPacket(ctx context.Context, direction string, p *network.Packet, srcPod, dstPod *api.PodInfo) {
	logger := klog.FromContext(ctx)

	srcPodStr, dstPodStr := "external", "external"
	if srcPod != nil {
		srcPodStr = srcPod.Namespace.Name + "/" + srcPod.Name
	}
	if dstPod != nil {
		dstPodStr = dstPod.Namespace.Name + "/" + dstPod.Name
	}

	logger.V(2).Info("Evaluating packet",
		"direction", direction,
		"srcPod", srcPodStr,
		"dstPod", dstPodStr,
		"packet", p,
	)
}
