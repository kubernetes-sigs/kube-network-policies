// pkg/podinfo/fallback_provider.go

package podinfo

import (
	"k8s.io/klog/v2"
	"sigs.k8s.io/kube-network-policies/pkg/api"
)

// FallbackPodInfoProvider combines a remote provider (the ipcache) with a
// local, NRI-based provider. The local provider knows which local pod owns an
// IP as soon as the runtime creates its sandbox, before the information
// reaches the ipcache, and the ipcache may still have the entry of a previous
// pod with the same IP.
type FallbackPodInfoProvider struct {
	cacheProvider api.PodInfoProvider // The ipcache client
	localProvider api.PodInfoProvider // The local, NRI-based provider
}

var _ api.PodInfoProvider = &FallbackPodInfoProvider{}

// NewFallbackPodInfoProvider creates a new FallbackPodInfoProvider.
func NewFallbackPodInfoProvider(
	cacheProvider api.PodInfoProvider,
	localProvider api.PodInfoProvider,
) api.PodInfoProvider {
	return &FallbackPodInfoProvider{
		cacheProvider: cacheProvider,
		localProvider: localProvider,
	}
}

// GetPodInfoByIP implements the api.PodInfoProvider interface.
func (p *FallbackPodInfoProvider) GetPodInfoByIP(ip string) (*api.PodInfo, bool) {
	// 1. The local provider decides which local pod owns the IP. The ipcache
	// entry has more details, like the container ports, so it is preferred
	// when it belongs to the same pod.
	if localInfo, found := p.localProvider.GetPodInfoByIP(ip); found {
		if cachedInfo, found := p.cacheProvider.GetPodInfoByIP(ip); found && cachedInfo.GetUID() == localInfo.GetUID() {
			return cachedInfo, true
		}
		klog.V(4).Infof("IP %s of pod %s/%s not in the ipcache yet, using the local NRI cache", ip, localInfo.GetNamespace().GetName(), localInfo.GetName())
		return localInfo, true
	}

	// 2. The pods of other nodes are only in the ipcache.
	return p.cacheProvider.GetPodInfoByIP(ip)
}
