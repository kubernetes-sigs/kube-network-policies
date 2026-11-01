// SPDX-License-Identifier: APACHE-2.0

package networkpolicy

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// verdictLogDropped counts the verdicts the VerdictLogger could not log
// because its buffer was full, the log destination is slower than the
// verdicts.
var verdictLogDropped = prometheus.NewCounter(prometheus.CounterOpts{
	Namespace: "kube_network_policies",
	Name:      "verdict_log_dropped",
	Help:      "Number of verdicts not logged because the verdict log buffer was full",
})

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
		prometheus.MustRegister(verdictLogDropped)
		prometheus.MustRegister(unresolvedIPCounter)
	})
}
