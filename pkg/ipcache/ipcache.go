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

package ipcache

import (
	"sigs.k8s.io/kube-network-policies/pkg/api"
)

// Store defines the interface for a key-value store that holds PodInfo.
type Store interface {
	GetPodInfoByIP(ip string) (*api.PodInfo, bool)
	Upsert(ip string, info *api.PodInfo) error
	Delete(ip string) error
	List() ([]*api.PodInfo, error)
	Clear() error // Clear removes all entries from the store.
	Close() error
}

// SyncMetadata contains the necessary information for a client to resume
// watching for changes from the correct point and ensure server identity.
type SyncMetadata struct {
	Revision  int64
	ClusterID uint64
	MemberID  uint64
}

// SyncMetadataStore defines the interface for a store that persists synchronization metadata.
type SyncMetadataStore interface {
	// GetSyncMetadata retrieves the last saved synchronization state.
	GetSyncMetadata() (*SyncMetadata, error)

	// SetSyncMetadata saves the current synchronization state.
	SetSyncMetadata(meta *SyncMetadata) error
}
