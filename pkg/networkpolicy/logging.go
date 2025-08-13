package networkpolicy

import (
	"context"

	"k8s.io/klog/v2"
	"sigs.k8s.io/kube-network-policies/pkg/network"
)

// NewLoggingEvaluator creates an evaluator that logs packet details.
func NewLoggingEvaluator(podInfoProvider PodInfoProvider) Evaluator {
	return Evaluator{
		Priority: 0, // Highest priority to log first
		Name:     "PacketLogger",
		Evaluate: func(ctx context.Context, p *network.Packet) (Verdict, error) {
			logger := klog.FromContext(ctx)
			srcPod, srcPodFound := podInfoProvider.GetPodInfoByIP(p.SrcIP.String())
			dstPod, dstPodFound := podInfoProvider.GetPodInfoByIP(p.DstIP.String())

			srcPodStr, dstPodStr := "none", "none"
			if srcPodFound {
				srcPodStr = srcPod.Namespace.Name + "/" + srcPod.Name
			}
			if dstPodFound {
				dstPodStr = dstPod.Namespace.Name + "/" + dstPod.Name
			}

			logger.V(2).Info("Evaluating packet", "srcPod", srcPodStr, "dstPod", dstPodStr)
			return VerdictNext, nil
		},
	}
}
