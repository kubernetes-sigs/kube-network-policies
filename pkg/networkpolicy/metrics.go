// SPDX-License-Identifier: APACHE-2.0

package networkpolicy

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// unresolvedIPCounter counts the packets whose source or destination IP does
// not resolve to a pod. Those are evaluated as external, which is expected
// for traffic from outside the cluster but also hides pods the agent does
// not know about.
var unresolvedIPCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: "kube_network_policies",
	Name:      "unresolved_ip_count",
	Help:      "Number of packets whose source or destination IP does not resolve to a pod and is evaluated as external",
}, []string{"endpoint"})

var registerMetricsOnce sync.Once

func registerMetrics() {
	registerMetricsOnce.Do(func() {
		prometheus.MustRegister(unresolvedIPCounter)
	})
}
