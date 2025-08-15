/*
Copyright 2025 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUTHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package ipcache

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/testing/protocmp"
	"sigs.k8s.io/kube-network-policies/pkg/api"
)

func TestLocalIPCache(t *testing.T) {
	cache := NewLocalIPCache()

	tests := []struct {
		name    string
		ip      string
		podInfo *api.PodInfo
	}{
		{
			name: "ipv4",
			ip:   "192.168.1.1",
			podInfo: &api.PodInfo{
				Name: "pod1",
			},
		},
		{
			name: "ipv6",
			ip:   "2001:db8::1",
			podInfo: &api.PodInfo{
				Name: "pod2",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test Upsert
			err := cache.Upsert(tt.ip, tt.podInfo)
			if err != nil {
				t.Fatalf("Upsert() error = %v", err)
			}

			// Test Get
			got, found := cache.GetPodInfoByIP(tt.ip)
			if !found {
				t.Fatalf("GetPodInfoForIP() not found for ip %s", tt.ip)
			}
			// Use protocmp.Transform() for a correct protobuf comparison
			if diff := cmp.Diff(tt.podInfo, got, protocmp.Transform()); diff != "" {
				t.Errorf("GetPodInfoForIP() mismatch (-want +got):\n%s", diff)
			}

			// Test Delete
			err = cache.Delete(tt.ip)
			if err != nil {
				t.Fatalf("Delete() error = %v", err)
			}

			// Verify deletion
			_, found = cache.GetPodInfoByIP(tt.ip)
			if found {
				t.Fatalf("GetPodInfoForIP() found for ip %s after deletion", tt.ip)
			}
		})
	}
}
