// SPDX-License-Identifier: APACHE-2.0

package networkpolicy

import (
	"context"
	"net/netip"

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

func (l *LoggingPolicy) Ready() bool {
	return true
}

func (l *LoggingPolicy) SetDataplaneSyncCallback(syncFn api.SyncFunc) {
	// No-op for AdminNetworkPolicy as it doesn't directly control dataplane rules.
	// The controller will handle syncing based on policy changes.
}

func (l *LoggingPolicy) ManagedIPs(ctx context.Context) ([]netip.Addr, bool, error) {
	// ManagedIPs returns nil as the logging policy does not manage any IPs.
	// It also returns false for divertAll as it does not divert all traffic.
	return nil, false, nil
}

// EvaluateIngress logs the details of an ingress packet and passes it to the next evaluator.
func (l *LoggingPolicy) EvaluateIngress(ctx context.Context, p *network.Packet, srcPod, dstPod *api.PodInfo) (api.Verdict, error) {
	logPacket(ctx, "Ingress", p, srcPod, dstPod)
	return api.VerdictNext, nil
}

// EvaluateEgress logs the details of an egress packet and passes it to the next evaluator.
func (l *LoggingPolicy) EvaluateEgress(ctx context.Context, p *network.Packet, srcPod, dstPod *api.PodInfo) (api.Verdict, error) {
	logPacket(ctx, "Egress", p, srcPod, dstPod)
	return api.VerdictNext, nil
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

	logger.Info("Evaluating packet",
		"direction", direction,
		"srcPod", srcPodStr,
		"dstPod", dstPodStr,
		"packet", p,
	)
}
