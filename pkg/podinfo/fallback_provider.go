// pkg/podinfo/fallback_provider.go

package podinfo

import (
	"k8s.io/klog/v2"
	"sigs.k8s.io/kube-network-policies/pkg/api"
)

// FallbackPodInfoProvider uses a primary provider (like a remote ipcache) and
// falls back to a local, NRI-based provider for immediate information on new pods.
// This solves the race condition where a pod's traffic is evaluated before its
// information has propagated to the central cache.
type FallbackPodInfoProvider struct {
	primaryProvider api.PodInfoProvider // The ipcache client
	localProvider   api.PodInfoProvider // The local, NRI-based provider
}

var _ api.PodInfoProvider = &FallbackPodInfoProvider{}

// NewFallbackPodInfoProvider creates a new FallbackPodInfoProvider.
func NewFallbackPodInfoProvider(
	primaryProvider api.PodInfoProvider,
	localProvider api.PodInfoProvider,
) api.PodInfoProvider {
	return &FallbackPodInfoProvider{
		primaryProvider: primaryProvider,
		localProvider:   localProvider,
	}
}

// GetPodInfoByIP implements the api.PodInfoProvider interface.
func (p *FallbackPodInfoProvider) GetPodInfoByIP(ip string) (*api.PodInfo, bool) {
	// 1. Try the primary provider (ipcache) first. This is the authoritative source.
	if podInfo, found := p.primaryProvider.GetPodInfoByIP(ip); found {
		return podInfo, true
	}

	// 2. If not found, fall back to the local NRI-based provider for immediate data.
	klog.V(4).Infof("IP %s not found in primary provider, falling back to local NRI cache", ip)
	return p.localProvider.GetPodInfoByIP(ip)
}
