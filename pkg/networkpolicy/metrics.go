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

var registerMetricsOnce sync.Once

func registerMetrics() {
	registerMetricsOnce.Do(func() {
		prometheus.MustRegister(verdictLogDropped)
	})
}
