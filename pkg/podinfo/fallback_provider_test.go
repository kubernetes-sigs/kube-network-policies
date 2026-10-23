package podinfo

import (
	"testing"

	"sigs.k8s.io/kube-network-policies/pkg/api"
)

type mapProvider map[string]*api.PodInfo

func (m mapProvider) GetPodInfoByIP(ip string) (*api.PodInfo, bool) {
	info, ok := m[ip]
	return info, ok
}

func TestFallbackPodInfoProvider(t *testing.T) {
	ns := &api.Namespace{Name: "ns"}
	cached := &api.PodInfo{Name: "web", Namespace: ns, UID: "uid-1", ContainerPorts: []*api.ContainerPort{{Name: "http", Port: 80}}}
	local := &api.PodInfo{Name: "web", Namespace: ns, UID: "uid-1"}
	staleCached := &api.PodInfo{Name: "job-old", Namespace: ns, UID: "uid-old"}
	remote := &api.PodInfo{Name: "remote", Namespace: ns, UID: "uid-r"}

	tests := []struct {
		name  string
		cache mapProvider
		local mapProvider
		want  *api.PodInfo
	}{
		{"same pod in both, ipcache details win", mapProvider{"10.0.0.1": cached}, mapProvider{"10.0.0.1": local}, cached},
		{"ipcache behind, local wins", mapProvider{}, mapProvider{"10.0.0.1": local}, local},
		{"ipcache has the previous pod, local wins", mapProvider{"10.0.0.1": staleCached}, mapProvider{"10.0.0.1": local}, local},
		{"remote pod only in the ipcache", mapProvider{"10.0.0.1": remote}, mapProvider{}, remote},
		{"unknown", mapProvider{}, mapProvider{}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewFallbackPodInfoProvider(tt.cache, tt.local)
			got, found := provider.GetPodInfoByIP("10.0.0.1")
			if found != (tt.want != nil) || got != tt.want {
				t.Errorf("GetPodInfoByIP() = %v, %v; want %v", got, found, tt.want)
			}
		})
	}
}
