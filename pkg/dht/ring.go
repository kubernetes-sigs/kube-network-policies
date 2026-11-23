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
	"cmp"
	"crypto/sha256"
	"encoding/binary"
	"slices"
)

// DefaultReplicationFactor is the default number of DHT replicas storing each pod IP.
const DefaultReplicationFactor = 3

// Member identifies one ready agent participating in the DHT.
type Member struct {
	NodeName string
	Address  string // host:port
}

type hashedMember struct {
	member   Member
	nameHash uint64
}

// Ring is an immutable 1-hop Rendezvous Hashing (Highest Random Weight) view
// built from the cluster's active agent list. It requires no virtual nodes and
// selects top-k distinct replicas deterministically in O(N * k) with zero
// per-node vnode memory overhead.
type Ring struct {
	members []hashedMember
	byNode  map[string]Member
}

// NewRing builds an immutable Rendezvous Hashing ring from members.
func NewRing(members []Member) *Ring {
	dedup := make(map[string]Member, len(members))
	for _, m := range members {
		if m.NodeName == "" || m.Address == "" {
			continue
		}
		if prev, ok := dedup[m.NodeName]; !ok || m.Address < prev.Address {
			dedup[m.NodeName] = m
		}
	}

	sorted := make([]hashedMember, 0, len(dedup))
	for _, m := range dedup {
		sorted = append(sorted, hashedMember{
			member:   m,
			nameHash: hashString(m.NodeName),
		})
	}
	slices.SortFunc(sorted, func(a, b hashedMember) int {
		return cmp.Compare(a.member.NodeName, b.member.NodeName)
	})

	return &Ring{
		members: sorted,
		byNode:  dedup,
	}
}

// Targets returns up to k distinct members with the highest Rendezvous Hashing
// scores for key.
func (r *Ring) Targets(key string, k int) []Member {
	if r == nil || len(r.members) == 0 || k <= 0 {
		return nil
	}
	if k > len(r.members) {
		k = len(r.members)
	}

	keyHash := hashString(key)

	type scored struct {
		score  uint64
		member Member
	}
	top := make([]scored, 0, k)
	for _, hm := range r.members {
		s := mix64(keyHash ^ hm.nameHash)
		if len(top) < k {
			top = append(top, scored{score: s, member: hm.member})
			// Bubble into descending order so top[len-1] is always the smallest.
			for i := len(top) - 1; i > 0 && higherScore(top[i].score, top[i].member.NodeName, top[i-1].score, top[i-1].member.NodeName); i-- {
				top[i], top[i-1] = top[i-1], top[i]
			}
			continue
		}
		last := top[k-1]
		if !higherScore(s, hm.member.NodeName, last.score, last.member.NodeName) {
			continue
		}
		top[k-1] = scored{score: s, member: hm.member}
		for i := k - 1; i > 0 && higherScore(top[i].score, top[i].member.NodeName, top[i-1].score, top[i-1].member.NodeName); i-- {
			top[i], top[i-1] = top[i-1], top[i]
		}
	}

	out := make([]Member, len(top))
	for i := range top {
		out[i] = top[i].member
	}
	return out
}

// Len returns the number of members in the ring.
func (r *Ring) Len() int {
	if r == nil {
		return 0
	}
	return len(r.members)
}

// HasNode reports whether nodeName is present in the ring.
func (r *Ring) HasNode(nodeName string) bool {
	if r == nil {
		return false
	}
	_, ok := r.byNode[nodeName]
	return ok
}

// Equal reports whether r and other contain the exact same members.
func (r *Ring) Equal(other *Ring) bool {
	if r == nil && other == nil {
		return true
	}
	if r == nil || other == nil {
		return false
	}
	if len(r.members) != len(other.members) {
		return false
	}
	for i := range r.members {
		if r.members[i].member != other.members[i].member {
			return false
		}
	}
	return true
}

func higherScore(sa uint64, nodeA string, sb uint64, nodeB string) bool {
	if sa != sb {
		return sa > sb
	}
	return nodeA < nodeB
}

func hashString(s string) uint64 {
	sum := sha256.Sum256([]byte(s))
	return binary.BigEndian.Uint64(sum[:8])
}

// mix64 is the SplitMix64 finalizer, providing uniform avalanche mixing for
// Rendezvous Hashing scores without allocations.
func mix64(z uint64) uint64 {
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}
