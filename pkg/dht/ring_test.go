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
	"fmt"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestRing_DeterminismAndDistinctTargets(t *testing.T) {
	membersA := []Member{
		{NodeName: "node-1", Address: "10.0.0.1:19091"},
		{NodeName: "node-2", Address: "10.0.0.2:19091"},
		{NodeName: "node-3", Address: "10.0.0.3:19091"},
		{NodeName: "node-4", Address: "10.0.0.4:19091"},
		{NodeName: "node-5", Address: "10.0.0.5:19091"},
	}
	membersB := slices.Clone(membersA)
	slices.Reverse(membersB)

	ringA := NewRing(membersA)
	ringB := NewRing(membersB)
	if !ringA.Equal(ringB) {
		t.Fatalf("expected rings built from reversed lists to be equal")
	}

	for i := range 200 {
		ip := fmt.Sprintf("10.244.%d.%d", i/10, i%10+1)
		gotA := ringA.Targets(ip, 3)
		gotB := ringB.Targets(ip, 3)
		if diff := cmp.Diff(gotA, gotB); diff != "" {
			t.Fatalf("Targets(%s) not deterministic (-a +b):\n%s", ip, diff)
		}
		if len(gotA) != 3 {
			t.Fatalf("Targets(%s) len = %d, want 3", ip, len(gotA))
		}
		seen := map[string]bool{}
		for _, m := range gotA {
			if seen[m.NodeName] {
				t.Fatalf("Targets(%s) returned duplicate node %s", ip, m.NodeName)
			}
			seen[m.NodeName] = true
		}
	}
}

func TestRing_MinimalKeyMovementOnNodeAdd(t *testing.T) {
	base := make([]Member, 0, 10)
	for i := range 10 {
		base = append(base, Member{
			NodeName: fmt.Sprintf("node-%d", i),
			Address:  fmt.Sprintf("10.0.0.%d:19091", i+1),
		})
	}
	before := NewRing(base)
	after := NewRing(append(slices.Clone(base), Member{
		NodeName: "node-10",
		Address:  "10.0.0.11:19091",
	}))

	const totalKeys = 1000
	moved := 0
	for i := range totalKeys {
		ip := fmt.Sprintf("10.244.%d.%d", i/250, i%250+1)
		if before.Targets(ip, 1)[0].NodeName != after.Targets(ip, 1)[0].NodeName {
			moved++
		}
	}
	// Ideal Rendezvous Hashing moves ~1/11 (~9.1%) of primary keys.
	if moved < 50 || moved > 150 {
		t.Fatalf("primary key movement on 10->11 add = %d/%d, want [50, 150]", moved, totalKeys)
	}
}

func TestRing_DeduplicationAndBounds(t *testing.T) {
	r := NewRing([]Member{
		{NodeName: "node-1", Address: "10.0.0.1:19091"},
		{NodeName: "node-1", Address: "10.0.0.9:19091"},
		{NodeName: "", Address: "10.0.0.2:19091"},
		{NodeName: "node-2", Address: ""},
	})
	if r.Len() != 1 || !r.HasNode("node-1") || r.HasNode("node-2") {
		t.Fatalf("unexpected ring state: len=%d", r.Len())
	}
	targets := r.Targets("10.244.0.1", 3)
	if len(targets) != 1 || targets[0].Address != "10.0.0.1:19091" {
		t.Fatalf("Targets() = %+v, want [10.0.0.1:19091]", targets)
	}
	if len(r.Targets("10.244.0.1", 0)) != 0 {
		t.Fatalf("expected empty targets for k=0")
	}
}
