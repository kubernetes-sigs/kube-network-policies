/*
Copyright 2025 The Kubernetes Authors.

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

package main

import (
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/kube-network-policies/pkg/api"
)

// fakeStore keeps the entries in memory with the ownership rules of the
// etcd store.
type fakeStore map[string]*api.PodInfo

func (s fakeStore) Upsert(ip string, info *api.PodInfo) error {
	s[ip] = info
	return nil
}

func (s fakeStore) DeleteIfOwner(ip string, uid string) error {
	if stored, ok := s[ip]; ok && stored.GetUID() == uid {
		delete(s, ip)
	}
	return nil
}

func makePod(name string, uid types.UID, ip string, phase v1.PodPhase) *v1.Pod {
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: name, UID: uid},
		Spec:       v1.PodSpec{NodeName: "node"},
		Status:     v1.PodStatus{Phase: phase, PodIPs: []v1.PodIP{{IP: ip}}},
	}
}

func TestPodIPReuse(t *testing.T) {
	store := fakeStore{}
	nsStore := cache.NewStore(cache.MetaNamespaceKeyFunc)
	_ = nsStore.Add(&v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns"}})
	nodeStore := cache.NewStore(cache.MetaNamespaceKeyFunc)
	ip := "10.0.0.1"

	// A Job pod runs and finishes, its IPs are released but stay in the status.
	jobRunning := makePod("job", "uid-job", ip, v1.PodRunning)
	updatePodInCache(store, nsStore, nodeStore, jobRunning)
	if got := store[ip]; got == nil || got.UID != "uid-job" {
		t.Fatalf("running pod not upserted: %v", got)
	}
	jobDone := makePod("job", "uid-job", ip, v1.PodSucceeded)
	deletePodFromCache(store, jobDone)
	if _, ok := store[ip]; ok {
		t.Fatal("entry of the finished pod not released")
	}

	// A terminal pod is never upserted, a namespace resync for example.
	updatePodInCache(store, nsStore, nodeStore, jobDone)
	if _, ok := store[ip]; ok {
		t.Fatal("terminal pod upserted")
	}

	// A new pod gets the IP.
	web := makePod("web", "uid-web", ip, v1.PodRunning)
	updatePodInCache(store, nsStore, nodeStore, web)
	if got := store[ip]; got == nil || got.UID != "uid-web" {
		t.Fatalf("new pod not upserted: %v", got)
	}

	// The finished pod is removed later by its TTL, the new owner stays.
	deletePodFromCache(store, jobDone)
	if got := store[ip]; got == nil || got.UID != "uid-web" {
		t.Fatalf("entry of the new owner lost: %v", got)
	}

	// The new owner is deleted.
	deletePodFromCache(store, web)
	if _, ok := store[ip]; ok {
		t.Fatal("entry of the deleted pod not released")
	}
}
