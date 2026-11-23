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
	"testing"
	"time"

	"sigs.k8s.io/kube-network-policies/pkg/api"
)

func TestReaderCache_SeparatePositiveAndNegativeLRUs(t *testing.T) {
	c := NewReaderCache(2)
	now := time.Unix(5000, 0)

	pod := &api.PodInfo{
		UID:       "uid-1",
		Name:      "web",
		Namespace: &api.Namespace{Name: "prod"},
		Labels:    map[string]string{"app": "web"},
	}
	c.SetPositive("10.0.0.1", pod, 10*time.Second, now)

	// Flood negative cache with external IPs — must NOT evict positive pod entry.
	for i := range 20 {
		c.SetNegative(fmt.Sprintf("198.51.100.%d", i), 5*time.Second, now)
	}

	got, found, hit := c.Get("10.0.0.1", now.Add(5*time.Second))
	if !hit || !found || got.Name != "web" {
		t.Fatalf("positive entry evicted by negative flood: got (%v, %v, %v)", got, found, hit)
	}

	// Positive TTL expiry.
	if _, _, hit := c.Get("10.0.0.1", now.Add(10*time.Second)); hit {
		t.Fatalf("expected positive entry expired at +10s")
	}

	// Negative hit and expiry.
	_, found, hit = c.Get("198.51.100.19", now.Add(4*time.Second))
	if !hit || found {
		t.Fatalf("expected negative hit at +4s, got found=%v hit=%v", found, hit)
	}
	if _, _, hit := c.Get("198.51.100.19", now.Add(5*time.Second)); hit {
		t.Fatalf("expected negative entry expired at +5s")
	}

	// Explicit Delete clears immediately.
	c.SetPositive("10.0.0.2", pod, 10*time.Second, now)
	c.Delete("10.0.0.2")
	if _, _, hit := c.Get("10.0.0.2", now.Add(time.Second)); hit {
		t.Fatalf("expected deleted entry to miss")
	}
}
