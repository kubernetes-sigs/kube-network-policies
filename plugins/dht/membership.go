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
	"errors"
	"net"
	"strconv"
	"sync"
	"time"

	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/labels"
	discoveryinformers "k8s.io/client-go/informers/discovery/v1"
	discoverylisters "k8s.io/client-go/listers/discovery/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	pkgdht "sigs.k8s.io/kube-network-policies/pkg/dht"
	"sigs.k8s.io/kube-network-policies/pkg/runner"
)

var errEndpointSlicesNotSynced = errors.New("EndpointSlice informer not synced yet")

// MembersFromEndpointSlices translates ready endpoints in Kubernetes
// EndpointSlices into 1-state Rendezvous Hashing members.
func MembersFromEndpointSlices(slices []*discoveryv1.EndpointSlice, defaultPort int) []pkgdht.Member {
	if len(slices) == 0 {
		return nil
	}

	// Prefer IPv4 on dual-stack clusters, falling back to IPv6 on IPv6-only clusters.
	family := discoveryv1.AddressTypeIPv6
	for _, es := range slices {
		if es.AddressType == discoveryv1.AddressTypeIPv4 {
			family = discoveryv1.AddressTypeIPv4
			break
		}
	}

	var members []pkgdht.Member
	for _, es := range slices {
		if es.AddressType != family {
			continue
		}
		port := resolveSlicePort(es, defaultPort)
		if port <= 0 {
			continue
		}
		portStr := strconv.Itoa(port)

		for _, ep := range es.Endpoints {
			if len(ep.Addresses) == 0 {
				continue
			}
			// Include endpoints whose Ready condition is true (or nil per EndpointSlice semantics).
			if ep.Conditions.Ready != nil && !*ep.Conditions.Ready {
				continue
			}
			nodeName := endpointNodeName(ep)
			if nodeName == "" {
				continue
			}
			members = append(members, pkgdht.Member{
				NodeName: nodeName,
				Address:  net.JoinHostPort(ep.Addresses[0], portStr),
			})
		}
	}
	return members
}

func resolveSlicePort(es *discoveryv1.EndpointSlice, defaultPort int) int {
	for _, p := range es.Ports {
		if p.Port != nil && *p.Port > 0 {
			return int(*p.Port)
		}
	}
	return defaultPort
}

func endpointNodeName(ep discoveryv1.Endpoint) string {
	if ep.NodeName != nil && *ep.NodeName != "" {
		return *ep.NodeName
	}
	if ep.TargetRef != nil && ep.TargetRef.Name != "" {
		return ep.TargetRef.Name
	}
	if len(ep.Addresses) > 0 {
		return ep.Addresses[0]
	}
	return ""
}

// WatchEndpointSlices synchronizes node's Rendezvous Hashing ring from
// epSliceInformer using a bounded-frequency runner to coalesce startup bursts
// across many EndpointSlices.
func WatchEndpointSlices(
	ctx context.Context,
	node *pkgdht.DHT,
	epSliceInformer discoveryinformers.EndpointSliceInformer,
	namespace string,
	defaultPort int,
) (cache.InformerSynced, error) {
	lister := epSliceInformer.Lister()
	hasSynced := epSliceInformer.Informer().HasSynced

	syncRunner := runner.NewBoundedFrequencyRunner(
		"dht-membership",
		func() error {
			if !hasSynced() {
				return errEndpointSlicesNotSynced
			}
			slices, err := listEndpointSlices(lister, namespace)
			if err != nil {
				klog.ErrorS(err, "listing DHT EndpointSlices")
				return err
			}
			node.UpdateMembers(MembersFromEndpointSlices(slices, defaultPort))
			return nil
		},
		100*time.Millisecond, // minInterval: coalesce 50-slice startup bursts
		250*time.Millisecond, // retryInterval
		5*time.Minute,        // maxInterval
	)

	var stopMu sync.Mutex
	stopped := false
	trigger := func() {
		stopMu.Lock()
		if !stopped {
			syncRunner.Run()
		}
		stopMu.Unlock()
	}

	reg, err := epSliceInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { trigger() },
		UpdateFunc: func(_, _ any) { trigger() },
		DeleteFunc: func(any) { trigger() },
	})
	if err != nil {
		return nil, err
	}

	stopRunner := make(chan struct{})
	go syncRunner.Loop(stopRunner)
	go func() {
		if cache.WaitForCacheSync(ctx.Done(), hasSynced) {
			trigger()
		}
		<-ctx.Done()
		_ = epSliceInformer.Informer().RemoveEventHandler(reg)
		stopMu.Lock()
		stopped = true
		stopMu.Unlock()
		close(stopRunner)
	}()
	return hasSynced, nil
}

func listEndpointSlices(lister discoverylisters.EndpointSliceLister, namespace string) ([]*discoveryv1.EndpointSlice, error) {
	if namespace != "" {
		return lister.EndpointSlices(namespace).List(labels.Everything())
	}
	return lister.List(labels.Everything())
}
