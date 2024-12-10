package nfqinterceptor

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/klog/v2"
)

var (
	nfqueueQueueTotal = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "nfqueue_queue_total",
		Help: "The number of packets currently queued and waiting to be processed by the application",
	}, []string{"queue"})
	nfqueueQueueDropped = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "nfqueue_queue_dropped",
		Help: "Number of packets that had to be dropped by the kernel because too many packets are already waiting for user space to send back the mandatory accept/drop verdicts",
	}, []string{"queue"})
	nfqueueUserDropped = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "nfqueue_user_dropped",
		Help: "Number of packets that were dropped within the netlink subsystem. Such drops usually happen when the corresponding socket buffer is full; that is, user space is not able to read 	messages fast enough",
	}, []string{"queue"})
	nfqueuePacketID = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "nfqueue_packet_id",
		Help: "ID of the most recent packet queued.",
	}, []string{"queue"})
)

var registerMetricsOnce sync.Once

// RegisterMetrics registers kube-proxy metrics.
func registerMetrics(ctx context.Context) {
	registerMetricsOnce.Do(func() {
		klog.Infof("Registering metrics")
		prometheus.MustRegister(nfqueueQueueTotal)
		prometheus.MustRegister(nfqueueQueueDropped)
		prometheus.MustRegister(nfqueueUserDropped)
		prometheus.MustRegister(nfqueuePacketID)
	})
}

// https://man7.org/linux/man-pages/man5/proc.5.html
type nfnetlinkQueue struct {
	queue_number  string // The ID of the queue.  This matches what is specified	in the --queue-num or --queue-balance options.
	peer_portid   int    // The netlink port ID subscribed to the queue.
	queue_total   int    // The number of packets currently queued and waiting to be processed by the application.
	copy_mode     int    // The copy mode of the queue. It is either 1 (metadata only) or 2 (also copy payload data to user space).
	copy_range    int    // Copy range; that is, how many bytes of packet payload should be copied to user space at most.
	queue_dropped int    // Number of packets that had to be dropped by the kernel because too many packets are already waiting for user space to send back the mandatory accept/drop verdicts.
	user_dropped  int    // Number of packets that were dropped within the netlink subsystem. Such drops usually happen when the corresponding socket buffer is full; that is, user space is not able to read 	messages fast enough.
	id_sequence   int    // sequence number.  Every queued packet is associated with a (32-bit) monotonically increasing sequence number. This shows the ID of the most recent packet queued.
	// dummy      int    // Field is always ‘1’ and is ignored, only kept for compatibility reasons.
}

func readNfnetlinkQueueStats() ([]nfnetlinkQueue, error) {
	const maxBufferSize = 1024 * 1024

	f, err := os.Open("/proc/net/netfilter/nfnetlink_queue")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	entries := []nfnetlinkQueue{}
	reader := io.LimitReader(f, maxBufferSize)

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 9 {
			return nil, fmt.Errorf("unexpected number of entries, got %d expected %d", len(fields), 9)
		}

		queue_number := fields[0]

		peer_portid, err := parseNfqueueField(fields[1])
		if err != nil {
			return nil, err
		}
		queue_total, err := parseNfqueueField(fields[2])
		if err != nil {
			return nil, err
		}
		copy_mode, err := parseNfqueueField(fields[3])
		if err != nil {
			return nil, err
		}
		copy_range, err := parseNfqueueField(fields[4])
		if err != nil {
			return nil, err
		}
		queue_dropped, err := parseNfqueueField(fields[5])
		if err != nil {
			return nil, err
		}
		user_dropped, err := parseNfqueueField(fields[6])
		if err != nil {
			return nil, err
		}
		id_sequence, err := parseNfqueueField(fields[7])
		if err != nil {
			return nil, err
		}

		nfqueueEntry := nfnetlinkQueue{
			queue_number:  queue_number,
			peer_portid:   peer_portid,
			queue_total:   queue_total,
			copy_mode:     copy_mode,
			copy_range:    copy_range,
			queue_dropped: queue_dropped,
			user_dropped:  user_dropped,
			id_sequence:   id_sequence,
		}

		entries = append(entries, nfqueueEntry)
	}
	return entries, nil
}

func parseNfqueueField(field string) (int, error) {
	val, err := strconv.Atoi(field)
	if err != nil {
		return 0, fmt.Errorf("couldn't parse %q field: %w", field, err)
	}
	return val, err
}
