// pkg/podinfo/fallback_provider.go

package podinfo

import (
	"k8s.io/klog/v2"
	"sigs.k8s.io/kube-network-policies/pkg/api"
)

// FallbackPodInfoProvider uses a local, NRI-based provider to find which Pod
// owns the IP of a local Pod, and the remote ipcache for the details of that
// Pod and for the Pods that NRI does not know about.
// NRI knows the Pod as soon as its sandbox is created, before its information
// has propagated to the central cache, and the cache may still have the entry
// of a previous Pod with the same IP.
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
	// 1. The local NRI-based provider knows which local Pod owns the IP. The
	// ipcache entry has more details, like the container ports, but it is
	// only used if it is the entry of the same Pod.
	if localInfo, found := getPodInfo(p.localProvider, ip); found {
		if cachedInfo, found := getPodInfo(p.cacheProvider, ip); found && sameUID(localInfo, cachedInfo) {
			return cachedInfo, true
		}
		klog.V(4).Infof("IP %s not found in the ipcache for Pod %s/%s with UID %q, using the local NRI cache", ip, localInfo.GetNamespace().GetName(), localInfo.GetName(), localInfo.GetUid())
		return localInfo, true
	}

	// 2. The Pods of other nodes are only in the ipcache.
	return getPodInfo(p.cacheProvider, ip)
}

// getPodInfo returns the PodInfo of the IP, a nil provider or PodInfo is not found.
func getPodInfo(provider api.PodInfoProvider, ip string) (*api.PodInfo, bool) {
	if provider == nil {
		return nil, false
	}
	podInfo, found := provider.GetPodInfoByIP(ip)
	if !found || podInfo == nil {
		return nil, false
	}
	return podInfo, true
}

// sameUID returns true if both PodInfos have the same UID, namespace and name.
// A PodInfo without UID may be of a previous Pod with the same name.
func sameUID(a, b *api.PodInfo) bool {
	return a.GetUid() != "" && a.GetUid() == b.GetUid() &&
		a.GetNamespace().GetName() == b.GetNamespace().GetName() &&
		a.GetName() == b.GetName()
}
