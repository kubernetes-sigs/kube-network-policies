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
	"fmt"
	"net"
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"

	"sigs.k8s.io/kube-network-policies/pkg/api"
	"sigs.k8s.io/kube-network-policies/pkg/ipcache"
)

// fakeStore is an in-memory ipcache server.
type fakeStore struct {
	entries map[string]*api.PodInfo
}

func (s *fakeStore) Upsert(ip string, info *api.PodInfo) error {
	s.entries[ip] = info
	return nil
}

func (s *fakeStore) DeleteIfOwner(ip string, owner *api.PodInfo) error {
	if stored, ok := s.entries[ip]; ok && api.SamePod(stored, owner) {
		delete(s.entries, ip)
	}
	return nil
}

// newTestTracker returns a tracker whose pod lister has the pods.
func newTestTracker(t *testing.T, pods ...*v1.Pod) (*tracker, *fakeStore) {
	t.Helper()
	factory := informers.NewSharedInformerFactory(fake.NewSimpleClientset(), 0)
	podInformer := factory.Core().V1().Pods()
	for _, pod := range pods {
		if err := podInformer.Informer().GetIndexer().Add(pod); err != nil {
			t.Fatalf("Add() failed: %v", err)
		}
	}
	nsStore := cache.NewStore(cache.MetaNamespaceKeyFunc)
	if err := nsStore.Add(&v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns1"}}); err != nil {
		t.Fatalf("Add() failed: %v", err)
	}
	store := &fakeStore{entries: map[string]*api.PodInfo{}}
	return &tracker{
		store:     store,
		podLister: podInformer.Lister(),
		nsStore:   nsStore,
		nodeStore: cache.NewStore(cache.MetaNamespaceKeyFunc),
	}, store
}

func makeTrackerPod(name, uid string, phase v1.PodPhase, ips ...string) *v1.Pod {
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: name, UID: types.UID(uid), Labels: map[string]string{"app": "test"}},
		Status:     v1.PodStatus{Phase: phase},
	}
	for _, ip := range ips {
		pod.Status.PodIPs = append(pod.Status.PodIPs, v1.PodIP{IP: ip})
	}
	if len(ips) > 0 {
		pod.Status.PodIP = ips[0]
	}
	return pod
}

func withPhase(pod *v1.Pod, phase v1.PodPhase) *v1.Pod {
	pod = pod.DeepCopy()
	pod.Status.Phase = phase
	return pod
}

// owner returns "namespace/name uid" of the entry of the IP, or "" if none.
func owner(store *fakeStore, ip string) string {
	info, ok := store.entries[ip]
	if !ok {
		return ""
	}
	return info.GetNamespace().GetName() + "/" + info.GetName() + " " + info.GetUid()
}

func assertOwner(t *testing.T, store *fakeStore, ip, want string) {
	t.Helper()
	if got := owner(store, ip); got != want {
		t.Errorf("entry of %s = %q, want %q", ip, got, want)
	}
}

func TestTracker_DeleteAfterIPReuse(t *testing.T) {
	podA := makeTrackerPod("pod-a", "uid-a", v1.PodRunning, "10.0.0.1", "fd00::1")
	podB := makeTrackerPod("pod-b", "uid-b", v1.PodRunning, "10.0.0.1", "fd00::1")
	tr, store := newTestTracker(t)
	tr.addPod(podA)
	tr.addPod(podB)

	// The delete event of pod-a arrives after pod-b got its IPs.
	tr.deletePod(podA)

	assertOwner(t, store, "10.0.0.1", "ns1/pod-b uid-b")
	assertOwner(t, store, "fd00::1", "ns1/pod-b uid-b")
}

func TestTracker_SameNameAnotherUID(t *testing.T) {
	oldPod := makeTrackerPod("web-0", "uid-a", v1.PodRunning, "10.0.0.1", "fd00::1")
	newPod := makeTrackerPod("web-0", "uid-b", v1.PodRunning, "10.0.0.1", "fd00::1")

	t.Run("delete of the previous pod", func(t *testing.T) {
		tr, store := newTestTracker(t)
		tr.addPod(newPod)

		tr.deletePod(oldPod)

		assertOwner(t, store, "10.0.0.1", "ns1/web-0 uid-b")
		assertOwner(t, store, "fd00::1", "ns1/web-0 uid-b")
	})

	t.Run("update to the new pod", func(t *testing.T) {
		// The informer missed the delete, the pod is replaced in an update.
		tr, store := newTestTracker(t)
		tr.addPod(oldPod)

		tr.updatePod(oldPod, newPod)

		assertOwner(t, store, "10.0.0.1", "ns1/web-0 uid-b")
		assertOwner(t, store, "fd00::1", "ns1/web-0 uid-b")
	})
}

func TestTracker_TerminalPod(t *testing.T) {
	for _, phase := range []v1.PodPhase{v1.PodSucceeded, v1.PodFailed} {
		t.Run(string(phase)+" update with the same IPs and labels", func(t *testing.T) {
			pod := makeTrackerPod("pod-a", "uid-a", v1.PodRunning, "10.0.0.1", "fd00::1")
			tr, store := newTestTracker(t)
			tr.addPod(pod)

			tr.updatePod(pod, withPhase(pod, phase))

			assertOwner(t, store, "10.0.0.1", "")
			assertOwner(t, store, "fd00::1", "")
		})

		t.Run(string(phase)+" add", func(t *testing.T) {
			tr, store := newTestTracker(t)

			tr.addPod(makeTrackerPod("pod-a", "uid-a", phase, "10.0.0.1", "fd00::1"))

			assertOwner(t, store, "10.0.0.1", "")
			assertOwner(t, store, "fd00::1", "")
		})

		t.Run(string(phase)+" namespace resync", func(t *testing.T) {
			tr, store := newTestTracker(t, makeTrackerPod("pod-a", "uid-a", phase, "10.0.0.1", "fd00::1"))

			tr.resyncNamespace("ns1")

			assertOwner(t, store, "10.0.0.1", "")
			assertOwner(t, store, "fd00::1", "")
		})
	}

	t.Run("terminal pod update after its IP was reused", func(t *testing.T) {
		podA := makeTrackerPod("pod-a", "uid-a", v1.PodRunning, "10.0.0.1", "fd00::1")
		tr, store := newTestTracker(t)
		tr.addPod(podA)
		tr.addPod(makeTrackerPod("pod-b", "uid-b", v1.PodRunning, "10.0.0.1", "fd00::1"))

		tr.updatePod(podA, withPhase(podA, v1.PodSucceeded))

		assertOwner(t, store, "10.0.0.1", "ns1/pod-b uid-b")
		assertOwner(t, store, "fd00::1", "ns1/pod-b uid-b")
	})
}

func TestTracker_PodLosesIP(t *testing.T) {
	before := makeTrackerPod("pod-a", "uid-a", v1.PodRunning, "10.0.0.1", "fd00::1", "10.0.0.2", "fd00::2")
	after := makeTrackerPod("pod-a", "uid-a", v1.PodRunning, "10.0.0.2", "fd00::2")

	t.Run("IPs are released", func(t *testing.T) {
		tr, store := newTestTracker(t)
		tr.addPod(before)

		tr.updatePod(before, after)

		assertOwner(t, store, "10.0.0.1", "")
		assertOwner(t, store, "fd00::1", "")
		assertOwner(t, store, "10.0.0.2", "ns1/pod-a uid-a")
		assertOwner(t, store, "fd00::2", "ns1/pod-a uid-a")
	})

	t.Run("IPs already reused by another pod", func(t *testing.T) {
		tr, store := newTestTracker(t)
		tr.addPod(before)
		tr.addPod(makeTrackerPod("pod-b", "uid-b", v1.PodRunning, "10.0.0.1", "fd00::1"))

		tr.updatePod(before, after)

		assertOwner(t, store, "10.0.0.1", "ns1/pod-b uid-b")
		assertOwner(t, store, "fd00::1", "ns1/pod-b uid-b")
		assertOwner(t, store, "10.0.0.2", "ns1/pod-a uid-a")
	})
}

func TestTracker_DeleteCurrentOwner(t *testing.T) {
	pod := makeTrackerPod("pod-a", "uid-a", v1.PodRunning, "10.0.0.1", "fd00::1")

	t.Run("delete", func(t *testing.T) {
		tr, store := newTestTracker(t)
		tr.addPod(pod)

		tr.deletePod(pod)

		assertOwner(t, store, "10.0.0.1", "")
		assertOwner(t, store, "fd00::1", "")
	})

	t.Run("delete missed by the informer", func(t *testing.T) {
		tr, store := newTestTracker(t)
		tr.addPod(pod)

		tr.deletePod(cache.DeletedFinalStateUnknown{Key: "ns1/pod-a", Obj: pod})

		assertOwner(t, store, "10.0.0.1", "")
		assertOwner(t, store, "fd00::1", "")
	})
}

func TestTracker_EntriesWithoutUID(t *testing.T) {
	// The entries written before the UID was added are matched by namespace and name.
	pod := makeTrackerPod("pod-a", "uid-a", v1.PodRunning, "10.0.0.1", "fd00::1")
	legacy := func(name string) *api.PodInfo {
		return &api.PodInfo{Name: name, Namespace: &api.Namespace{Name: "ns1"}}
	}

	t.Run("entry of the pod", func(t *testing.T) {
		tr, store := newTestTracker(t)
		store.entries["10.0.0.1"] = legacy("pod-a")
		store.entries["fd00::1"] = legacy("pod-a")

		tr.deletePod(pod)

		assertOwner(t, store, "10.0.0.1", "")
		assertOwner(t, store, "fd00::1", "")
	})

	t.Run("entry of another pod", func(t *testing.T) {
		tr, store := newTestTracker(t)
		store.entries["10.0.0.1"] = legacy("pod-b")
		store.entries["fd00::1"] = legacy("pod-b")

		tr.deletePod(pod)

		assertOwner(t, store, "10.0.0.1", "ns1/pod-b ")
		assertOwner(t, store, "fd00::1", "ns1/pod-b ")
	})
}

func TestTracker_HostNetworkPod(t *testing.T) {
	pod := makeTrackerPod("pod-h", "uid-h", v1.PodRunning, "192.168.0.1")
	pod.Spec.HostNetwork = true
	tr, store := newTestTracker(t, pod)

	tr.addPod(pod)
	tr.resyncNamespace("ns1")

	assertOwner(t, store, "192.168.0.1", "")
}

func TestTracker_NamespaceResync(t *testing.T) {
	// Only the pods that the lister has are upserted, with the current state.
	running := makeTrackerPod("pod-a", "uid-a", v1.PodRunning, "10.0.0.1", "fd00::1")
	tr, store := newTestTracker(t, running)

	tr.resyncNamespace("ns1")

	assertOwner(t, store, "10.0.0.1", "ns1/pod-a uid-a")
	assertOwner(t, store, "fd00::1", "ns1/pod-a uid-a")
}

func TestTracker_EtcdStore(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find a free port: %v", err)
	}
	listenURL := fmt.Sprintf("http://%s", l.Addr().String())
	l.Close()
	etcdStore, err := ipcache.NewEtcdStore(listenURL, t.TempDir())
	if err != nil {
		t.Fatalf("NewEtcdStore() failed: %v", err)
	}
	t.Cleanup(func() { etcdStore.Close() })
	tr, _ := newTestTracker(t)
	tr.store = etcdStore
	entry := func(ip string) string {
		info, ok := etcdStore.GetPodInfoByIP(ip)
		if !ok {
			return ""
		}
		return info.GetNamespace().GetName() + "/" + info.GetName() + " " + info.GetUid()
	}

	podA := makeTrackerPod("web-0", "uid-a", v1.PodRunning, "10.0.0.1", "fd00::1")
	podB := makeTrackerPod("web-0", "uid-b", v1.PodRunning, "10.0.0.1", "fd00::1")
	podC := makeTrackerPod("pod-c", "uid-c", v1.PodRunning, "10.0.0.3", "fd00::3")
	tr.addPod(podA)
	tr.addPod(podB)
	tr.addPod(podC)

	// The delete of the previous web-0 keeps the entries of the new one.
	tr.deletePod(podA)
	for _, ip := range []string{"10.0.0.1", "fd00::1"} {
		if got := entry(ip); got != "ns1/web-0 uid-b" {
			t.Errorf("entry of %s = %q, want %q", ip, got, "ns1/web-0 uid-b")
		}
	}

	// A pod that finished releases its IPs.
	tr.updatePod(podC, withPhase(podC, v1.PodSucceeded))
	for _, ip := range []string{"10.0.0.3", "fd00::3"} {
		if got := entry(ip); got != "" {
			t.Errorf("entry of %s = %q, want none", ip, got)
		}
	}
}
