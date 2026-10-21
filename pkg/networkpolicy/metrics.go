// SPDX-License-Identifier: APACHE-2.0

package networkpolicy

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	unresolvedPodIPs = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "kube_network_policies",
		Name:      "unresolved_pod_ips_total",
		Help:      "Number of packet source and destination IPs that did not resolve to a Pod and were evaluated as external",
	}, []string{"direction"})

	// The counters of both directions are exported even if they are zero.
	unresolvedSourceIPs      = unresolvedPodIPs.WithLabelValues("source")
	unresolvedDestinationIPs = unresolvedPodIPs.WithLabelValues("destination")
)

var registerMetricsOnce sync.Once

// registerMetrics registers the policy engine metrics in the default registry.
func registerMetrics() {
	registerMetricsOnce.Do(func() {
		prometheus.MustRegister(unresolvedPodIPs)
	})
}
