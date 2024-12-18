package networkpolicy

import (
	"context"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/klog/v2"
)

var (
	packetProcessingHist = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "packet_process_time",
		Help:    "Time it has taken to process each packet (microseconds)",
		Buckets: []float64{1, 10, 50, 200, 500, 750, 1000, 2000, 5000, 10000, 100000},
	}, []string{"protocol", "family"})

	packetProcessingSum = prometheus.NewSummary(prometheus.SummaryOpts{
		Name: "packet_process_duration_microseconds",
		Help: "A summary of the packet processing durations in microseconds.",
		Objectives: map[float64]float64{
			0.5:  0.05,  // 50th percentile with a max. absolute error of 0.05.
			0.9:  0.01,  // 90th percentile with a max. absolute error of 0.01.
			0.99: 0.001, // 99th percentile with a max. absolute error of 0.001.
		},
	})
	packetCounterVec = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "packet_count",
		Help: "Number of packets",
	}, []string{"protocol", "family", "verdict"})
)

var registerMetricsOnce sync.Once

// RegisterMetrics registers kube-proxy metrics.
func registerMetrics(ctx context.Context) {
	registerMetricsOnce.Do(func() {
		klog.Infof("Registering metrics")
		prometheus.MustRegister(packetProcessingHist)
		prometheus.MustRegister(packetProcessingSum)
		prometheus.MustRegister(packetCounterVec)
	})
}
