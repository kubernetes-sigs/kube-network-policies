package nfqinterceptor

import (
	"context"
	"fmt"
	"time"

	nfqueue "github.com/florianl/go-nfqueue"
	"github.com/mdlayher/netlink"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/knftables"
	"sigs.k8s.io/kube-network-policies/pkg/networkpolicy"
)

// Network policies are hard to implement efficiently, and in large clusters this is
// translated to performance and scalability problems. Most of the existing
// implementations use the same approach of processing the APIs and transforming them in
// the corresponding dataplane implementation; commonly this may be iptables, nftables,
// ebpf or ovs. This takes a different approach, it uses the NFQUEUE functionality
// implemented in netfilter to process the first packet of each connection in userspace
// and emit a verdict. The advantage is that the dataplane implementation does not need to
// represent all the complex logic. There are also some performance improvements that can
// be applied, such as to restrict the packets that are sent to userspace to the ones that
// have network policies only. This effectively means that network policies are applied
// ONLY at the time the connection is initatied by whatever the conntrack kernel
// understand by NEW connection.
//
// https://home.regit.org/netfilter-en/using-nfqueue-and-libnetfilter_queue/
// https://netfilter.org/projects/libnetfilter_queue/doxygen/html/

const (
	controllerName = "kube-network-policies"
	podIPIndex     = "podIPKeyIndex"
	syncKey        = "dummy-key" // use the same key to sync to aggregate the events
	podV4IPsSet    = "podips-v4"
	podV6IPsSet    = "podips-v6"
)

// should probably take its own config?
func New(config networkpolicy.Config) (*nfqInterceptor, error) {
	nft, err := knftables.New(knftables.InetFamily, config.NFTableName)
	if err != nil {
		return nil, err
	}
	return &nfqInterceptor{
		//nfq isn't populated till run which is wierd
		nft:                 nft,
		FailOpen:            config.FailOpen,
		queueid:             config.QueueID,
		NetfilterBug1766Fix: config.NetfilterBug1766Fix,
		interceptAll:        config.AdminNetworkPolicy || config.BaselineAdminNetworkPolicy,
	}, nil
}

type nfqInterceptor struct {
	nft                 knftables.Interface // install the necessary nftables rules
	flushed             bool
	FailOpen            bool
	queueid             int
	NetfilterBug1766Fix bool
	interceptAll        bool //!c.config.AdminNetworkPolicy && !c.config.BaselineAdminNetworkPolicy
}

func (n *nfqInterceptor) Run(ctx context.Context, renderVerdict func(context.Context, networkpolicy.Packet) networkpolicy.Verdict) error {
	logger := klog.FromContext(ctx)
	registerMetrics(ctx)
	go wait.UntilWithContext(ctx, func(ctx context.Context) {
		queues, err := readNfnetlinkQueueStats()
		if err != nil {
			logger.Error(err, "reading nfqueue stats")
			return
		}
		logger.V(4).Info("Obtained metrics for queues", "nqueues", len(queues))
		for _, q := range queues {
			logger.V(4).Info("Updating metrics", "queue", q.id_sequence)
			nfqueueQueueTotal.WithLabelValues(q.queue_number).Set(float64(q.queue_total))
			nfqueueQueueDropped.WithLabelValues(q.queue_number).Set(float64(q.queue_dropped))
			nfqueueUserDropped.WithLabelValues(q.queue_number).Set(float64(q.user_dropped))
			nfqueuePacketID.WithLabelValues(q.queue_number).Set(float64(q.id_sequence))
		}

	}, 30*time.Second)

	var flags uint32
	// https://netfilter.org/projects/libnetfilter_queue/doxygen/html/group__Queue.html
	// the kernel will not normalize offload packets,
	// i.e. your application will need to be able to handle packets larger than the mtu.
	// Normalization is expensive, so this flag should always be set.
	// This also solves a bug with SCTP
	// https://github.com/aojea/kube-netpol/issues/8
	// https://bugzilla.netfilter.org/show_bug.cgi?id=1742
	flags = nfqueue.NfQaCfgFlagGSO
	if n.FailOpen {
		flags += nfqueue.NfQaCfgFlagFailOpen
	}

	// Set configuration options for nfqueue
	config := nfqueue.Config{
		NfQueue:      uint16(n.queueid),
		Flags:        flags,
		MaxPacketLen: 128, // only interested in the headers
		MaxQueueLen:  1024,
		Copymode:     nfqueue.NfQnlCopyPacket, // headers
		WriteTimeout: 100 * time.Millisecond,
	}
	nf, err := nfqueue.Open(&config)
	if err != nil {
		logger.Info("could not open nfqueue socket", "error", err)
		return err
	}

	defer func() {
		n.cleanNFTablesRules(ctx)
		nf.Close()
	}()

	logger.Info("Syncing nftables rules")
	_ = n.Sync(ctx, sets.Set[string]{}, sets.Set[string]{}) //why bother with empties?

	fn := func(a nfqueue.Attribute) int {
		verdict := networkpolicy.Drop
		if n.FailOpen {
			verdict = networkpolicy.Accept
		}

		packet, err := networkpolicy.ParsePacket(*a.Payload)
		if err != nil {
			logger.Error(err, "Can not process packet, applying default policy", "id", *a.PacketID, "failOpen", n.FailOpen)
			nf.SetVerdict(packet.Id, int(verdict))
			return 0
		}
		packet.Id = *a.PacketID
		verdict = renderVerdict(ctx, packet)
		// log error and return default if not Accept or Drop?
		nf.SetVerdict(packet.Id, int(verdict))
		return 0
	}
	// Register your function to listen on nflog group 100
	err = nf.RegisterWithErrorFunc(ctx, fn, func(err error) int {
		if opError, ok := err.(*netlink.OpError); ok {
			if opError.Timeout() || opError.Temporary() {
				return 0
			}
		}
		logger.Info("Could not receive message", "error", err)
		return 0
	})
	if err != nil {
		logger.Info("could not open nfqueue socket", "error", err)
		return err
	}

	//wait here or we'll cleanup nftable rukes and close the socket
	<-ctx.Done()

	return nil
}

// Sync adds the necessary rules to process the first connection packets in userspace
// and check if network policies must apply.
// TODO: We can divert only the traffic affected by network policies using a set in nftables or an IPset.
func (c *nfqInterceptor) Sync(ctx context.Context, podV4IPs, podV6IPs sets.Set[string]) error {
	table := &knftables.Table{
		Comment: knftables.PtrTo("rules for kubernetes NetworkPolicy"),
	}
	tx := c.nft.NewTransaction()
	// do it once to delete the existing table
	if !c.flushed {
		tx.Add(table)
		tx.Delete(table)
		c.flushed = true
	}
	tx.Add(table)

	// only if no admin network policies are used
	if !c.interceptAll {
		// add set with Local Pod IPs impacted by network policies
		tx.Add(&knftables.Set{
			Name:    podV4IPsSet,
			Type:    "ipv4_addr",
			Comment: ptr.To("Local V4 Pod IPs with Network Policies"),
		})
		tx.Flush(&knftables.Set{
			Name: podV4IPsSet,
		})
		tx.Add(&knftables.Set{
			Name:    podV6IPsSet,
			Type:    "ipv6_addr",
			Comment: ptr.To("Local V6 Pod IPs with Network Policies"),
		})
		tx.Flush(&knftables.Set{
			Name: podV6IPsSet,
		})

		for _, ip := range podV4IPs.UnsortedList() {
			tx.Add(&knftables.Element{
				Set: podV4IPsSet,
				Key: []string{ip},
			})
		}
		for _, ip := range podV6IPs.UnsortedList() {
			tx.Add(&knftables.Element{
				Set: podV6IPsSet,
				Key: []string{ip},
			})
		}
	}
	// Process the packets that are, usually on the FORWARD hook, but
	// IPVS packets follow a different path in netfilter, so we process
	// everything in the POSTROUTING hook before SNAT happens.
	// Ref: https://github.com/kubernetes-sigs/kube-network-policies/issues/46
	hook := knftables.PostroutingHook
	chainName := string(hook)
	tx.Add(&knftables.Chain{
		Name:     chainName,
		Type:     knftables.PtrTo(knftables.FilterType),
		Hook:     knftables.PtrTo(hook),
		Priority: knftables.PtrTo(knftables.SNATPriority + "-5"),
	})
	tx.Flush(&knftables.Chain{
		Name: chainName,
	})

	// DNS is processed by addDNSRacersWorkaroundRules()
	// TODO: remove once kernel fix is on most distros
	if c.NetfilterBug1766Fix {
		tx.Add(&knftables.Rule{
			Chain:   chainName,
			Rule:    "udp dport 53 accept",
			Comment: ptr.To("process DNS traffic on PREROUTING hook with network policy enforcement to avoid netfilter race condition bug"),
		})
	}

	// IPv6 needs ICMP Neighbor Discovery to work
	tx.Add(&knftables.Rule{
		Chain: chainName,
		Rule: knftables.Concat(
			"icmpv6", "type", "{", "nd-neighbor-solicit, nd-neighbor-advert", "}", "accept"),
	})
	// Don't process traffic generated from the root user in the Node, it can block kubelet probes
	// or system daemons that depend on the internal node traffic to not be blocked.
	// Ref: https://github.com/kubernetes-sigs/kube-network-policies/issues/65
	tx.Add(&knftables.Rule{
		Chain: chainName,
		Rule:  "meta skuid 0 accept",
	})
	// instead of aggregating all the expresion in one rule, use two different
	// rules to understand if is causing issues with UDP packets with the same
	// tuple (https://github.com/kubernetes-sigs/kube-network-policies/issues/12)
	tx.Add(&knftables.Rule{
		Chain: chainName,
		Rule: knftables.Concat(
			"ct", "state", "established,related", "accept"),
	})

	action := fmt.Sprintf("queue num %d", c.queueid)
	if c.FailOpen {
		action += " bypass"
	}

	// only if no admin network policies are used
	if !c.interceptAll {
		tx.Add(&knftables.Rule{
			Chain: chainName,
			Rule: knftables.Concat(
				"ip", "saddr", "@", podV4IPsSet, action,
			),
			Comment: ptr.To("process IPv4 traffic with network policy enforcement"),
		})

		tx.Add(&knftables.Rule{
			Chain: chainName,
			Rule: knftables.Concat(
				"ip", "daddr", "@", podV4IPsSet, action,
			),
			Comment: ptr.To("process IPv4 traffic with network policy enforcement"),
		})

		tx.Add(&knftables.Rule{
			Chain: chainName,
			Rule: knftables.Concat(
				"ip6", "saddr", "@", podV6IPsSet, action,
			),
			Comment: ptr.To("process IPv6 traffic with network policy enforcement"),
		})

		tx.Add(&knftables.Rule{
			Chain: chainName,
			Rule: knftables.Concat(
				"ip6", "daddr", "@", podV6IPsSet, action,
			),
			Comment: ptr.To("process IPv6 traffic with network policy enforcement"),
		})
	} else {
		tx.Add(&knftables.Rule{
			Chain: chainName,
			Rule:  action,
		})
	}

	if c.NetfilterBug1766Fix {
		c.addDNSRacersWorkaroundRules(ctx, tx)
	}

	if err := c.nft.Run(ctx, tx); err != nil {
		klog.FromContext(ctx).Info("syncing nftables rules", "error", err)
		return err
	}
	return nil
}

// To avoid a kernel bug caused by UDP DNS request racing with conntrack
// process the DNS packets only on the PREROUTING hook after DNAT happens
// so we can see the resolved destination IPs, typically the ones of the Pods
// that are used for the Kubernetes DNS Service.
// xref: https://github.com/kubernetes-sigs/kube-network-policies/issues/12
// This can be removed once all kernels contain the fix in
// https://github.com/torvalds/linux/commit/8af79d3edb5fd2dce35ea0a71595b6d4f9962350
// TODO: remove once kernel fix is on most distros
func (c *nfqInterceptor) addDNSRacersWorkaroundRules(ctx context.Context, tx *knftables.Transaction) {
	hook := knftables.PreroutingHook
	chainName := string(hook)
	tx.Add(&knftables.Chain{
		Name:     chainName,
		Type:     knftables.PtrTo(knftables.FilterType),
		Hook:     knftables.PtrTo(hook),
		Priority: knftables.PtrTo(knftables.DNATPriority + "+5"),
	})
	tx.Flush(&knftables.Chain{
		Name: chainName,
	})

	action := fmt.Sprintf("queue num %d", c.queueid)
	if c.FailOpen {
		action += " bypass"
	}

	if !c.interceptAll {
		tx.Add(&knftables.Rule{
			Chain: chainName,
			Rule: knftables.Concat(
				"ip", "saddr", "@", podV4IPsSet, "udp dport 53", action,
			),
			Comment: ptr.To("process IPv4 traffic destined to a DNS server with network policy enforcement"),
		})

		tx.Add(&knftables.Rule{
			Chain: chainName,
			Rule: knftables.Concat(
				"ip", "daddr", "@", podV4IPsSet, "udp dport 53", action,
			),
			Comment: ptr.To("process IPv4 traffic destined to a DNS server with network policy enforcement"),
		})

		tx.Add(&knftables.Rule{
			Chain: chainName,
			Rule: knftables.Concat(
				"ip6", "saddr", "@", podV6IPsSet, "udp dport 53", action,
			),
			Comment: ptr.To("process IPv6 traffic destined to a DNS server with network policy enforcement"),
		})

		tx.Add(&knftables.Rule{
			Chain: chainName,
			Rule: knftables.Concat(
				"ip6", "daddr", "@", podV6IPsSet, "udp dport 53", action,
			),
			Comment: ptr.To("process IPv6 traffic destined to a DNS server with network policy enforcement"),
		})
	} else {
		tx.Add(&knftables.Rule{
			Chain: chainName,
			Rule: knftables.Concat(
				"udp dport 53", action,
			),
		})
	}
}

func (c *nfqInterceptor) cleanNFTablesRules(ctx context.Context) {
	tx := c.nft.NewTransaction()
	// Add+Delete is idempotent and won't return an error if the table doesn't already
	// exist.
	tx.Add(&knftables.Table{})
	tx.Delete(&knftables.Table{})

	// When this function is called, the ctx is likely cancelled. So
	// we only use it for logging, and create a context with timeout
	// for nft.Run. There is a grace period of 5s in main, so we keep
	// this timeout shorter
	nctx, cancel := context.WithTimeout(context.Background(), time.Second*4)
	defer cancel()
	if err := c.nft.Run(nctx, tx); err != nil {
		klog.FromContext(ctx).Error(err, "deleting nftables rules")
	}
}
