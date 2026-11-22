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
	"errors"
	"fmt"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
	"sigs.k8s.io/kube-network-policies/pkg/api"
)

const (
	defaultMaxStoreRecords = 100_000
	maxAllowedTTL          = 5 * time.Minute
)

// Record is the wire representation of one versioned IP-to-PodInfo entry.
// All durations are relative (TTLMS, AgeMS) so replicas never compare wall
// clocks across nodes. Namespace labels are stripped on the wire and hydrated
// locally by each reader.
type Record struct {
	IP        string `json:"ip"`
	OwnerNode string `json:"owner_node"`
	Seq       uint64 `json:"seq"`
	Tombstone bool   `json:"tombstone,omitempty"`
	TTLMS     int64  `json:"ttl_ms"`
	AgeMS     int64  `json:"age_ms,omitempty"`
	PodInfoPB []byte `json:"pod_info,omitempty"`
}

type storedRecord struct {
	wire       Record
	podInfo    *api.PodInfo // immutable decoded PodInfo; nil when Tombstone
	receivedAt time.Time    // replica-local arrival time
	expiresAt  time.Time    // replica-local expiry time
}

// Store holds DHT replica records in memory, partitioned by (IP, OwnerNode).
// Keeping per-owner entries allows clean cross-node IP reuse on shared-IPAM
// CNIs (such as AWS VPC CNI) while allowing concurrent reads via RLock.
type Store struct {
	mu         sync.RWMutex
	records    map[string]map[string]*storedRecord // ip -> ownerNode -> entry
	total      int
	maxRecords int
}

// NewStore creates a bounded in-memory replica store.
func NewStore(maxRecords int) *Store {
	if maxRecords <= 0 {
		maxRecords = defaultMaxStoreRecords
	}
	return &Store{
		records:    make(map[string]map[string]*storedRecord),
		maxRecords: maxRecords,
	}
}

// Put validates and stores rec if its sequence number is newer than any
// non-expired existing record for (IP, OwnerNode). When rejected as stale,
// maxSeq reports the existing record's sequence number so a restarted owner
// after a backward clock step can advance its sequence counter and retry.
func (s *Store) Put(rec Record, now time.Time) (accepted bool, maxSeq uint64, err error) {
	if rec.IP == "" {
		return false, 0, errors.New("record ip is empty")
	}
	if rec.OwnerNode == "" {
		return false, 0, errors.New("record owner_node is empty")
	}
	if rec.TTLMS <= 0 {
		return false, 0, errors.New("record ttl_ms must be positive")
	}
	ttl := min(time.Duration(rec.TTLMS)*time.Millisecond, maxAllowedTTL)

	var decoded *api.PodInfo
	var canonicalPB []byte
	if !rec.Tombstone {
		if len(rec.PodInfoPB) == 0 {
			return false, 0, errors.New("alive record must include pod_info")
		}
		decoded = &api.PodInfo{}
		if err := proto.Unmarshal(rec.PodInfoPB, decoded); err != nil {
			return false, 0, fmt.Errorf("unmarshaling pod_info: %w", err)
		}
		// Enforce authoritative owner node and strip namespace labels.
		decoded.Node = &api.Node{Name: rec.OwnerNode}
		if decoded.Namespace != nil {
			decoded.Namespace = &api.Namespace{Name: decoded.Namespace.Name}
		}
		canonicalPB, err = proto.Marshal(decoded)
		if err != nil {
			return false, 0, fmt.Errorf("marshaling canonical pod_info: %w", err)
		}
	}

	wire := Record{
		IP:        rec.IP,
		OwnerNode: rec.OwnerNode,
		Seq:       rec.Seq,
		Tombstone: rec.Tombstone,
		TTLMS:     ttl.Milliseconds(),
		PodInfoPB: canonicalPB,
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	byOwner, ok := s.records[rec.IP]
	if ok {
		if existing, exists := byOwner[rec.OwnerNode]; exists && existing.expiresAt.After(now) {
			if rec.Seq <= existing.wire.Seq {
				return false, existing.wire.Seq, nil
			}
			// Preserve receivedAt on pure lease refresh so cross-node handoff
			// age reflects when this owner actually claimed or mutated the IP.
			receivedAt := now
			if !existing.wire.Tombstone && !wire.Tombstone && bytesEqual(existing.wire.PodInfoPB, wire.PodInfoPB) {
				receivedAt = existing.receivedAt
			}
			byOwner[rec.OwnerNode] = &storedRecord{
				wire:       wire,
				podInfo:    decoded,
				receivedAt: receivedAt,
				expiresAt:  now.Add(ttl),
			}
			return true, wire.Seq, nil
		}
	}

	// Inserting a new (or replacing an expired) entry.
	isNew := !ok || byOwner[rec.OwnerNode] == nil
	if isNew && s.total >= s.maxRecords {
		return false, 0, fmt.Errorf("replica store capacity reached (%d)", s.maxRecords)
	}
	if !ok {
		byOwner = make(map[string]*storedRecord, 1)
		s.records[rec.IP] = byOwner
	}
	if isNew {
		s.total++
	}
	byOwner[rec.OwnerNode] = &storedRecord{
		wire:       wire,
		podInfo:    decoded,
		receivedAt: now,
		expiresAt:  now.Add(ttl),
	}
	return true, wire.Seq, nil
}

// Get returns all non-expired per-owner records (alive and tombstone) for ip
// under a shared read lock. Returning tombstones allows readers to suppress
// stale lower-sequence ALIVE records from lagging replicas.
func (s *Store) Get(ip string, now time.Time) []Record {
	s.mu.RLock()
	defer s.mu.RUnlock()

	byOwner := s.records[ip]
	if len(byOwner) == 0 {
		return nil
	}
	out := make([]Record, 0, len(byOwner))
	for _, entry := range byOwner {
		if !entry.expiresAt.After(now) {
			continue
		}
		rec := entry.wire
		rec.TTLMS = entry.expiresAt.Sub(now).Milliseconds()
		rec.AgeMS = max(now.Sub(entry.receivedAt).Milliseconds(), 0)
		out = append(out, rec)
	}
	return out
}

// GC removes expired records and returns the number of remaining records.
func (s *Store) GC(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	for ip, byOwner := range s.records {
		for owner, entry := range byOwner {
			if !entry.expiresAt.After(now) {
				delete(byOwner, owner)
				s.total--
			}
		}
		if len(byOwner) == 0 {
			delete(s.records, ip)
		}
	}
	return s.total
}

// Len returns the number of stored records (alive and tombstone).
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.total
}

// ResolveRecords merges per-owner records gathered from one or more replicas.
// For each OwnerNode, the highest Seq wins (so a newer tombstone suppresses a
// stale ALIVE on a lagging replica). Across distinct surviving ALIVE owners,
// the most recently updated entry (lowest AgeMS) wins without relying on
// synchronized wall clocks across nodes.
func ResolveRecords(records []Record) (*api.PodInfo, bool, error) {
	if len(records) == 0 {
		return nil, false, nil
	}

	bestByOwner := make(map[string]Record, len(records))
	for _, r := range records {
		if r.OwnerNode == "" {
			continue
		}
		prev, ok := bestByOwner[r.OwnerNode]
		if !ok || r.Seq > prev.Seq || (r.Seq == prev.Seq && r.AgeMS < prev.AgeMS) {
			bestByOwner[r.OwnerNode] = r
		}
	}

	var winner *Record
	for _, r := range bestByOwner {
		if r.Tombstone || len(r.PodInfoPB) == 0 {
			continue
		}
		candidate := r
		if winner == nil ||
			candidate.AgeMS < winner.AgeMS ||
			(candidate.AgeMS == winner.AgeMS && candidate.OwnerNode > winner.OwnerNode) {
			winner = &candidate
		}
	}
	if winner == nil {
		return nil, false, nil
	}

	podInfo := &api.PodInfo{}
	if err := proto.Unmarshal(winner.PodInfoPB, podInfo); err != nil {
		return nil, false, fmt.Errorf("unmarshaling resolved pod_info: %w", err)
	}
	return podInfo, true, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
