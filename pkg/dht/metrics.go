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
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	registerMetricsOnce sync.Once

	dhtLookupsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "kube_network_policies",
		Subsystem: "dht",
		Name:      "lookups_total",
		Help:      "Total number of remote PodInfo lookups handled by the DHT.",
	}, []string{"result"})

	dhtRPCDurationSeconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "kube_network_policies",
		Subsystem: "dht",
		Name:      "rpc_duration_seconds",
		Help:      "Latency of outbound DHT HTTP/2 calls in seconds.",
		Buckets:   []float64{0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25},
	}, []string{"method", "status"})

	dhtStoreRecords = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "kube_network_policies",
		Subsystem: "dht",
		Name:      "store_records",
		Help:      "Current number of records held in this node's DHT replica store.",
	})

	dhtRingMembers = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "kube_network_policies",
		Subsystem: "dht",
		Name:      "ring_members",
		Help:      "Current number of active members in the DHT ring.",
	})
)

func registerMetrics() {
	registerMetricsOnce.Do(func() {
		prometheus.MustRegister(
			dhtLookupsTotal,
			dhtRPCDurationSeconds,
			dhtStoreRecords,
			dhtRingMembers,
		)
	})
}
