package podinfo

import (
	"testing"

	"google.golang.org/protobuf/proto"
	"sigs.k8s.io/kube-network-policies/pkg/api"
)

// fakePodInfoProvider returns the record of an IP, an IP with a nil record is
// found without a record.
type fakePodInfoProvider map[string]*api.PodInfo

func (f fakePodInfoProvider) GetPodInfoByIP(ip string) (*api.PodInfo, bool) {
	podInfo, ok := f[ip]
	return podInfo, ok
}

// nriRecord is what NRI knows about a local Pod, it has no container ports
// and no node labels.
func nriRecord(name, uid string) *api.PodInfo {
	return &api.PodInfo{
		Name:      name,
		Uid:       uid,
		Labels:    map[string]string{"app": name, "source": "nri"},
		Namespace: &api.Namespace{Name: "ns1", Labels: map[string]string{"source": "nri"}},
		Node:      &api.Node{Name: "node1"},
	}
}

// cacheRecord is what the IP cache knows about a Pod, every field that the
// policies use differs from the NRI record.
func cacheRecord(namespace, name, uid string) *api.PodInfo {
	return &api.PodInfo{
		Name:           name,
		Uid:            uid,
		Labels:         map[string]string{"app": name, "source": "cache"},
		ContainerPorts: []*api.ContainerPort{{Name: "http", Port: 80, Protocol: "TCP"}},
		Namespace:      &api.Namespace{Name: namespace, Labels: map[string]string{"source": "cache"}},
		Node:           &api.Node{Name: "node1", Labels: map[string]string{"zone": "a"}},
		ClusterId:      "cluster1",
	}
}

// assertPodInfo compares all the fields of the record, so a record of the
// other provider, or merged with it, does not match.
func assertPodInfo(t *testing.T, got *api.PodInfo, ok bool, want *api.PodInfo) {
	t.Helper()
	if want == nil {
		if ok || got != nil {
			t.Errorf("GetPodInfoByIP() = %v, %v; want not found", got, ok)
		}
		return
	}
	if !ok || !proto.Equal(got, want) {
		t.Errorf("GetPodInfoByIP() = %v, %v; want %v", got, ok, want)
	}
}

func TestFallbackPodInfoProvider(t *testing.T) {
	tests := []struct {
		name   string
		local  *api.PodInfo // what NRI knows about the owner of the IP, nil if none
		cached *api.PodInfo // the IP cache entry, nil if none
		want   string       // "nri", "cache" or "" if not found
	}{
		{
			name:   "cache entry of the NRI owner",
			local:  nriRecord("pod-b", "uid-b"),
			cached: cacheRecord("ns1", "pod-b", "uid-b"),
			want:   "cache",
		},
		{
			name:   "cache entry of the previous pod",
			local:  nriRecord("pod-b", "uid-b"),
			cached: cacheRecord("ns1", "pod-a", "uid-a"),
			want:   "nri",
		},
		{
			name:   "cache entry of a previous pod with the same name",
			local:  nriRecord("web-0", "uid-b"),
			cached: cacheRecord("ns1", "web-0", "uid-a"),
			want:   "nri",
		},
		{
			name:   "cache entry without UID",
			local:  nriRecord("pod-b", "uid-b"),
			cached: cacheRecord("ns1", "pod-b", ""),
			want:   "nri",
		},
		{
			name:   "NRI owner without UID",
			local:  nriRecord("pod-b", ""),
			cached: cacheRecord("ns1", "pod-b", "uid-b"),
			want:   "nri",
		},
		{
			name:   "NRI owner and cache entry without UID",
			local:  nriRecord("pod-b", ""),
			cached: cacheRecord("ns1", "pod-b", ""),
			want:   "nri",
		},
		{
			name:   "cache entry with the same UID and another name",
			local:  nriRecord("pod-b", "uid-b"),
			cached: cacheRecord("ns1", "pod-c", "uid-b"),
			want:   "nri",
		},
		{
			name:   "cache entry with the same UID in another namespace",
			local:  nriRecord("pod-b", "uid-b"),
			cached: cacheRecord("ns2", "pod-b", "uid-b"),
			want:   "nri",
		},
		{
			name:  "NRI owner without cache entry",
			local: nriRecord("pod-b", "uid-b"),
			want:  "nri",
		},
		{
			name:   "remote pod",
			cached: cacheRecord("ns1", "pod-r", "uid-r"),
			want:   "cache",
		},
		{
			name:   "remote pod without UID",
			cached: cacheRecord("ns1", "pod-r", ""),
			want:   "cache",
		},
		{
			name: "unknown IP",
			want: "",
		},
	}
	for _, tt := range tests {
		for _, ip := range []string{"10.0.0.1", "fd00::1"} {
			t.Run(tt.name+"/"+ip, func(t *testing.T) {
				// The providers return copies, so the records that are
				// compared can not be modified.
				local := fakePodInfoProvider{}
				if tt.local != nil {
					local[ip] = proto.Clone(tt.local).(*api.PodInfo)
				}
				cache := fakePodInfoProvider{}
				if tt.cached != nil {
					cache[ip] = proto.Clone(tt.cached).(*api.PodInfo)
				}
				provider := NewFallbackPodInfoProvider(cache, local)

				podInfo, ok := provider.GetPodInfoByIP(ip)

				var want *api.PodInfo
				switch tt.want {
				case "nri":
					want = tt.local
				case "cache":
					want = tt.cached
				}
				assertPodInfo(t, podInfo, ok, want)
			})
		}
	}
}

func TestFallbackPodInfoProvider_MissingRecords(t *testing.T) {
	const ip = "10.0.0.1"
	tests := []struct {
		name  string
		local api.PodInfoProvider
		cache api.PodInfoProvider
		want  *api.PodInfo
	}{
		{
			name:  "NRI disabled",
			cache: fakePodInfoProvider{ip: cacheRecord("ns1", "pod-a", "uid-a")},
			want:  cacheRecord("ns1", "pod-a", "uid-a"),
		},
		{
			name:  "NRI disabled without cache entry",
			cache: fakePodInfoProvider{},
		},
		{
			name:  "NRI owner without record",
			local: fakePodInfoProvider{ip: nil},
			cache: fakePodInfoProvider{ip: cacheRecord("ns1", "pod-a", "uid-a")},
			want:  cacheRecord("ns1", "pod-a", "uid-a"),
		},
		{
			name:  "cache entry without record",
			local: fakePodInfoProvider{ip: nriRecord("pod-b", "uid-b")},
			cache: fakePodInfoProvider{ip: nil},
			want:  nriRecord("pod-b", "uid-b"),
		},
		{
			name:  "no records",
			local: fakePodInfoProvider{ip: nil},
			cache: fakePodInfoProvider{ip: nil},
		},
		{
			name:  "NRI record without namespace",
			local: fakePodInfoProvider{ip: {Name: "pod-b", Uid: "uid-b"}},
			cache: fakePodInfoProvider{ip: cacheRecord("ns1", "pod-b", "uid-b")},
			want:  &api.PodInfo{Name: "pod-b", Uid: "uid-b"},
		},
		{
			name:  "cache entry without namespace",
			local: fakePodInfoProvider{ip: nriRecord("pod-b", "uid-b")},
			cache: fakePodInfoProvider{ip: {Name: "pod-b", Uid: "uid-b"}},
			want:  nriRecord("pod-b", "uid-b"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("GetPodInfoByIP() panicked: %v", r)
				}
			}()
			provider := NewFallbackPodInfoProvider(tt.cache, tt.local)

			podInfo, ok := provider.GetPodInfoByIP(ip)

			assertPodInfo(t, podInfo, ok, tt.want)
		})
	}
}
