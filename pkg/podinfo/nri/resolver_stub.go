//go:build !linux

package nri

import (
	"context"
	"errors"

	coreinformers "k8s.io/client-go/informers/core/v1"
	"sigs.k8s.io/kube-network-policies/pkg/api"
	"sigs.k8s.io/kube-network-policies/pkg/podinfo"
)

var _ podinfo.IPResolver = &NRIResolver{}
var _ api.PodInfoProvider = &NRIResolver{}

// EventHandler receives notifications when local pod sandboxes start,
// synchronize, or stop.
type EventHandler struct {
	OnUpsert func(pod *api.PodInfo)
	OnDelete func(uid string, ips []string)
}

// Option configures an NRIResolver at construction time.
type Option func(*NRIResolver)

// WithEventHandler is a no-op on non-Linux platforms.
func WithEventHandler(EventHandler) Option { return func(*NRIResolver) {} }

// NRIResolver is a stub implementation of the NRI-based resolver for non-Linux platforms.
type NRIResolver struct{}

// SetEventHandler is a no-op on non-Linux platforms.
func (p *NRIResolver) SetEventHandler(EventHandler) {}

// NewNRIResolver returns an error on non-Linux platforms.
func NewNRIResolver(ctx context.Context, nodeName string, namespaceInformer coreinformers.NamespaceInformer, opts ...Option) (*NRIResolver, error) {
	return nil, errors.New("NRI resolver is only supported on Linux")
}

// LookupPod always returns false on non-Linux platforms.
func (p *NRIResolver) LookupPod(ip string) (string, bool) {
	return "", false
}

// GetPodInfoByIP always returns false on non-Linux platforms.
func (p *NRIResolver) GetPodInfoByIP(ip string) (*api.PodInfo, bool) {
	return nil, false
}
