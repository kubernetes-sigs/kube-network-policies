/*
Copyright 2026 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package dht

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sync"

	v1 "k8s.io/api/core/v1"
	coreinformers "k8s.io/client-go/informers/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	"sigs.k8s.io/kube-network-policies/pkg/api"
	pkgdht "sigs.k8s.io/kube-network-policies/pkg/dht"
	"sigs.k8s.io/kube-network-policies/pkg/podinfo"
)

// Provider composes the local podinfo.InformerProvider (reusing standard NRI +
// node-scoped PodInformer + Namespace resolution) with a remote 1-hop DHT for
// pods on other nodes, and publishes local pod IP lifecycle events to the DHT
// asynchronously.
type Provider struct {
	nodeName      string
	localProvider api.PodInfoProvider
	remoteDHT     *pkgdht.DHT
	nsLister      corelisters.NamespaceLister

	// Tracks local IP -> UID ownership for non-blocking DHT publication so
	// stale apiserver events never overwrite an IP reclaimed by a newer pod.
	mu          sync.Mutex
	ownerByIP   map[string]string   // ip -> pod UID
	ipsByUID    map[string][]string // pod UID -> published IPs
	stoppedUIDs map[string]struct{} // UIDs already torn down by NRI
}

var _ api.PodInfoProvider = &Provider{}
var _ api.PodInfoResolver = &Provider{}

// NewProvider creates a Provider that reuses podinfo.NewInformerProvider for
// local pods, hydrates Namespace labels on remote DHT lookups, and registers
// non-blocking PodInformer handlers to publish local pods into remoteDHT.
func NewProvider(
	nodeName string,
	localPodInformer coreinformers.PodInformer,
	nsInformer coreinformers.NamespaceInformer,
	localResolver podinfo.LocalResolver,
	remoteDHT *pkgdht.DHT,
) (*Provider, error) {
	infResolver, err := podinfo.NewInformerResolver(localPodInformer.Informer())
	if err != nil {
		return nil, fmt.Errorf("creating local informer resolver: %w", err)
	}
	localProvider, err := podinfo.NewInformerProvider(
		localPodInformer,
		nsInformer,
		nil,
		localResolver,
		[]podinfo.IPResolver{infResolver},
	)
	if err != nil {
		return nil, fmt.Errorf("creating local podinfo provider: %w", err)
	}

	p := &Provider{
		nodeName:      nodeName,
		localProvider: localProvider,
		remoteDHT:     remoteDHT,
		ownerByIP:     make(map[string]string),
		ipsByUID:      make(map[string][]string),
		stoppedUIDs:   make(map[string]struct{}),
	}
	if nsInformer != nil {
		p.nsLister = nsInformer.Lister()
	}

	_, err = localPodInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			if pod, ok := obj.(*v1.Pod); ok {
				p.onPodUpsert(pod)
			}
		},
		UpdateFunc: func(_, cur any) {
			if pod, ok := cur.(*v1.Pod); ok {
				p.onPodUpsert(pod)
			}
		},
		DeleteFunc: func(obj any) {
			pod, ok := obj.(*v1.Pod)
			if !ok {
				if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
					pod, _ = tombstone.Obj.(*v1.Pod)
				}
			}
			if pod != nil {
				p.onPodDelete(pod)
			}
		},
	})
	if err != nil {
		return nil, fmt.Errorf("registering local pod event handler: %w", err)
	}
	return p, nil
}

// OnNRIUpsert publishes a newly started local sandbox into the DHT immediately
// (non-blocking) before kubelet reports Status.PodIPs to the apiserver.
func (p *Provider) OnNRIUpsert(pod *api.PodInfo) {
	if pod == nil || len(pod.IPs) == 0 {
		return
	}
	uid := pod.GetUID()

	// Prefer enriched PodInfo from localProvider (includes ContainerPorts and
	// mutated labels) if the informer already has the same pod UID. Done before
	// acquiring p.mu to avoid lock ordering dependencies with localProvider.
	enriched := make(map[string]*api.PodInfo, len(pod.IPs))
	for _, ip := range pod.IPs {
		if ip == "" {
			continue
		}
		toPublish := pod
		if localInfo, ok := p.localProvider.GetPodInfoByIP(ip); ok && localInfo.GetUID() == uid {
			toPublish = localInfo
		}
		enriched[ip] = toPublish
	}

	p.mu.Lock()
	if uid != "" {
		delete(p.stoppedUIDs, uid)
	}
	for ip, toPublish := range enriched {
		p.claimLocked(uid, ip)
		p.remoteDHT.Publish(ip, toPublish)
	}
	p.mu.Unlock()
}

// OnNRIDelete marks a stopped sandbox's UID as stopped and publishes tombstones
// (non-blocking) for any IPs still owned by that UID.
func (p *Provider) OnNRIDelete(uid string, ips []string) {
	p.mu.Lock()
	if uid != "" {
		p.stoppedUIDs[uid] = struct{}{}
	}
	p.releaseLocked(uid, ips)
	p.mu.Unlock()
}

// GetPodInfoByIP implements api.PodInfoProvider.
func (p *Provider) GetPodInfoByIP(ip string) (*api.PodInfo, bool) {
	info, found, err := p.ResolvePodInfoByIP(context.Background(), ip)
	if err != nil {
		return nil, false
	}
	return info, found
}

// ResolvePodInfoByIP implements api.PodInfoResolver. Local pods are served
// directly from podinfo.InformerProvider; remote pods come from the 1-hop DHT
// with Namespace.Labels hydrated locally via a shallow copy (no proto.Clone).
func (p *Provider) ResolvePodInfoByIP(ctx context.Context, ip string) (*api.PodInfo, bool, error) {
	if localInfo, ok := p.localProvider.GetPodInfoByIP(ip); ok {
		return localInfo, true, nil
	}
	remoteInfo, found, err := p.remoteDHT.ResolvePodInfoByIP(ctx, ip)
	if err != nil || !found || remoteInfo == nil {
		return nil, false, err
	}
	return p.hydrateNamespaceLabels(remoteInfo), true, nil
}

func (p *Provider) onPodUpsert(pod *v1.Pod) {
	if pod.Spec.NodeName != p.nodeName {
		return
	}
	if !api.PodOwnsIPs(pod) {
		p.onPodDelete(pod)
		return
	}

	uid := api.PodUID(pod)
	info := api.NewPodInfo(pod, nil, nil, "")

	p.mu.Lock()
	defer p.mu.Unlock()

	// Ignore stale apiserver updates for a sandbox NRI already tore down.
	if _, stopped := p.stoppedUIDs[uid]; stopped {
		return
	}

	// Collect all IPs for this UID (from PodStatus plus any NRI-claimed IPs).
	ipSet := make(map[string]struct{}, len(info.IPs))
	for _, ip := range info.IPs {
		if ip == "" {
			continue
		}
		// Never overwrite an IP already claimed by a newer pod UID.
		if owner, exists := p.ownerByIP[ip]; exists && owner != "" && owner != uid {
			continue
		}
		ipSet[ip] = struct{}{}
	}
	for _, ip := range p.ipsByUID[uid] {
		if p.ownerByIP[ip] == uid {
			ipSet[ip] = struct{}{}
		}
	}

	// Release any IP previously owned by uid that disappeared from PodStatus
	// (only if PodStatus is non-empty, so NRI-only IPs before PodStatus arrives stay live).
	if len(info.IPs) > 0 {
		var dropped []string
		for _, oldIP := range p.ipsByUID[uid] {
			if !slices.Contains(info.IPs, oldIP) {
				dropped = append(dropped, oldIP)
				delete(ipSet, oldIP)
			}
		}
		if len(dropped) > 0 {
			p.releaseLocked(uid, dropped)
		}
	}

	for ip := range ipSet {
		p.claimLocked(uid, ip)
		p.remoteDHT.Publish(ip, info)
	}
}

func (p *Provider) onPodDelete(pod *v1.Pod) {
	if pod.Spec.NodeName != p.nodeName {
		return
	}
	uid := api.PodUID(pod)
	var podIPs []string
	for _, podIP := range pod.Status.PodIPs {
		if podIP.IP != "" {
			podIPs = append(podIPs, podIP.IP)
		}
	}

	p.mu.Lock()
	delete(p.stoppedUIDs, uid)
	allIPs := slices.Concat(p.ipsByUID[uid], podIPs)
	p.releaseLocked(uid, allIPs)
	p.mu.Unlock()
}

func (p *Provider) claimLocked(uid, ip string) {
	p.ownerByIP[ip] = uid
	if uid == "" {
		return
	}
	if !slices.Contains(p.ipsByUID[uid], ip) {
		p.ipsByUID[uid] = append(p.ipsByUID[uid], ip)
	}
}

func (p *Provider) releaseLocked(uid string, ips []string) {
	for _, ip := range ips {
		if cur, ok := p.ownerByIP[ip]; ok && (uid == "" || cur == uid) {
			delete(p.ownerByIP, ip)
			p.remoteDHT.Delete(ip)
		}
	}
	if uid == "" {
		return
	}
	remaining := p.ipsByUID[uid][:0]
	for _, ip := range p.ipsByUID[uid] {
		if p.ownerByIP[ip] == uid {
			remaining = append(remaining, ip)
		}
	}
	if len(remaining) == 0 {
		delete(p.ipsByUID, uid)
	} else {
		p.ipsByUID[uid] = remaining
	}
}

// hydrateNamespaceLabels shallow-copies the immutable remote PodInfo and
// attaches fresh Namespace.Labels from the local Namespace informer.
func (p *Provider) hydrateNamespaceLabels(info *api.PodInfo) *api.PodInfo {
	if info == nil || info.Namespace == nil || p.nsLister == nil {
		return info
	}
	ns, err := p.nsLister.Get(info.Namespace.Name)
	if err != nil {
		return info
	}
	if len(ns.Labels) == 0 && len(info.Namespace.Labels) == 0 {
		return info
	}
	return &api.PodInfo{
		Name:           info.Name,
		Labels:         info.Labels,
		ContainerPorts: info.ContainerPorts,
		Namespace: &api.Namespace{
			Name:   info.Namespace.Name,
			Labels: maps.Clone(ns.Labels),
		},
		Node:        info.Node,
		LastUpdated: info.LastUpdated,
		ClusterId:   info.ClusterId,
		IPs:         info.IPs,
		UID:         info.UID,
	}
}
