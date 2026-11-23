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
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"sigs.k8s.io/kube-network-policies/pkg/api"
)

func mustMarshalPod(t *testing.T, uid, ns, name, node string, labels map[string]string, ip string) []byte {
	t.Helper()
	pb, err := proto.Marshal(&api.PodInfo{
		UID:       uid,
		Name:      name,
		Namespace: &api.Namespace{Name: ns, Labels: map[string]string{"should": "strip"}},
		Node:      &api.Node{Name: node},
		Labels:    labels,
		IPs:       []string{ip},
	})
	if err != nil {
		t.Fatalf("proto.Marshal: %v", err)
	}
	return pb
}

func TestStore_ValidationAndCapacity(t *testing.T) {
	s := NewStore(2)
	now := time.Unix(1000, 0)

	cases := []struct {
		name string
		rec  Record
	}{
		{name: "empty ip", rec: Record{OwnerNode: "n1", Seq: 1, TTLMS: 1000, Tombstone: true}},
		{name: "empty owner", rec: Record{IP: "10.0.0.1", Seq: 1, TTLMS: 1000, Tombstone: true}},
		{name: "zero ttl", rec: Record{IP: "10.0.0.1", OwnerNode: "n1", Seq: 1, Tombstone: true}},
		{name: "alive without podinfo", rec: Record{IP: "10.0.0.1", OwnerNode: "n1", Seq: 1, TTLMS: 1000}},
		{name: "corrupt podinfo", rec: Record{IP: "10.0.0.1", OwnerNode: "n1", Seq: 1, TTLMS: 1000, PodInfoPB: []byte{0xff, 0xff}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := s.Put(tc.rec, now); err == nil {
				t.Fatalf("Put(%s) expected error, got nil", tc.name)
			}
		})
	}

	// Capacity cap of 2 records.
	for i, ip := range []string{"10.0.0.1", "10.0.0.2"} {
		if _, _, err := s.Put(Record{IP: ip, OwnerNode: "n1", Seq: uint64(i + 1), Tombstone: true, TTLMS: 1000}, now); err != nil {
			t.Fatalf("Put(%s) error = %v", ip, err)
		}
	}
	if _, _, err := s.Put(Record{IP: "10.0.0.3", OwnerNode: "n1", Seq: 3, Tombstone: true, TTLMS: 1000}, now); err == nil {
		t.Fatalf("expected store capacity error on 3rd record")
	}
}

func TestStore_SeqRejectionExpiredReplaceAndCanonicalOwner(t *testing.T) {
	s := NewStore(10)
	now := time.Unix(2000, 0)

	// PodInfo claims wrong node "spoof-node" and includes namespace labels;
	// Store must overwrite Node.Name = OwnerNode and strip Namespace.Labels.
	pb := mustMarshalPod(t, "u1", "prod", "web", "spoof-node", map[string]string{"app": "web"}, "10.0.1.5")
	ok, seq, err := s.Put(Record{
		IP:        "10.0.1.5",
		OwnerNode: "node-1",
		Seq:       100,
		TTLMS:     10_000,
		PodInfoPB: pb,
	}, now)
	if err != nil || !ok || seq != 100 {
		t.Fatalf("Put() = (%v, %d, %v), want (true, 100, nil)", ok, seq, err)
	}

	recs := s.Get("10.0.1.5", now.Add(time.Second))
	if len(recs) != 1 {
		t.Fatalf("Get() len = %d, want 1", len(recs))
	}
	got, found, err := ResolveRecords(recs)
	if err != nil || !found {
		t.Fatalf("ResolveRecords() = (%v, %v, %v)", got, found, err)
	}
	if got.GetNode().GetName() != "node-1" {
		t.Fatalf("canonical Node.Name = %q, want node-1", got.GetNode().GetName())
	}
	if len(got.GetNamespace().GetLabels()) != 0 {
		t.Fatalf("expected Namespace.Labels stripped, got %v", got.GetNamespace().GetLabels())
	}

	// Lower Seq while unexpired -> rejected with existing maxSeq=100.
	ok, maxSeq, err := s.Put(Record{
		IP:        "10.0.1.5",
		OwnerNode: "node-1",
		Seq:       50,
		Tombstone: true,
		TTLMS:     10_000,
	}, now.Add(2*time.Second))
	if err != nil || ok || maxSeq != 100 {
		t.Fatalf("stale Put() = (%v, %d, %v), want (false, 100, nil)", ok, maxSeq, err)
	}

	// After expiry, lower Seq IS accepted (recovers cleanly from restart + backward clock).
	ok, _, err = s.Put(Record{
		IP:        "10.0.1.5",
		OwnerNode: "node-1",
		Seq:       50,
		TTLMS:     10_000,
		PodInfoPB: pb,
	}, now.Add(15*time.Second))
	if err != nil || !ok {
		t.Fatalf("Put() after expiry = (%v, %v), want (true, nil)", ok, err)
	}
}

func TestResolveRecords_TombstoneSuppressionAndCrossNodeReuse(t *testing.T) {
	pbA := mustMarshalPod(t, "uid-a", "dev", "pod-a", "node-1", map[string]string{"app": "a"}, "10.0.1.5")
	pbB := mustMarshalPod(t, "uid-b", "prod", "pod-b", "node-2", map[string]string{"app": "b"}, "10.0.1.5")

	// Replica 1 has TOMBSTONE(node-1, seq=20); lagging Replica 2 still has ALIVE(node-1, seq=10).
	// Tombstone MUST suppress the stale ALIVE record.
	pod, found, err := ResolveRecords([]Record{
		{IP: "10.0.1.5", OwnerNode: "node-1", Seq: 20, Tombstone: true, AgeMS: 100},
		{IP: "10.0.1.5", OwnerNode: "node-1", Seq: 10, PodInfoPB: pbA, AgeMS: 5000},
	})
	if err != nil || found || pod != nil {
		t.Fatalf("expected tombstone to suppress stale ALIVE, got (%v, %v, %v)", pod, found, err)
	}

	// Cross-node IP reuse: node-2 claimed 10.0.1.5 more recently (lower AgeMS)
	// than node-1's still-unexpired record.
	pod, found, err = ResolveRecords([]Record{
		{IP: "10.0.1.5", OwnerNode: "node-1", Seq: 10, PodInfoPB: pbA, AgeMS: 5000},
		{IP: "10.0.1.5", OwnerNode: "node-2", Seq: 1, PodInfoPB: pbB, AgeMS: 200},
	})
	if err != nil || !found || pod.UID != "uid-b" {
		t.Fatalf("cross-node reuse ResolveRecords() = (%v, %v, %v), want uid-b", pod, found, err)
	}
}

func TestStore_GC(t *testing.T) {
	s := NewStore(10)
	now := time.Unix(3000, 0)
	_, _, _ = s.Put(Record{IP: "10.0.0.1", OwnerNode: "n1", Seq: 1, Tombstone: true, TTLMS: 5000}, now)
	_, _, _ = s.Put(Record{IP: "10.0.0.2", OwnerNode: "n1", Seq: 2, Tombstone: true, TTLMS: 20_000}, now)

	if rem := s.GC(now.Add(10 * time.Second)); rem != 1 {
		t.Fatalf("GC(+10s) = %d, want 1", rem)
	}
	if rem := s.GC(now.Add(25 * time.Second)); rem != 0 {
		t.Fatalf("GC(+25s) = %d, want 0", rem)
	}
}
