package dataplane

import (
	"context"
	"fmt"
	"time"

	nfqueue "github.com/florianl/go-nfqueue"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"

	"sigs.k8s.io/kube-network-policies/pkg/network"
	"sigs.k8s.io/kube-network-policies/pkg/networkpolicy"
	"sigs.k8s.io/kube-network-policies/pkg/runner"
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
	syncKey        = "dummy-key" // use the same key to sync to aggregate the events
	podV4IPsSet    = "podips-v4"
	podV6IPsSet    = "podips-v6"
)

type Config struct {
	FailOpen            bool // allow traffic if the controller is not available
	QueueID             int
	NetfilterBug1766Fix bool
	NFTableName         string // if other projects use this controllers they need to be able to use their own table name
}

func (c *Config) Defaults() error {
	if c.QueueID == 0 {
		c.QueueID = 100
	}

	if c.NFTableName == "" {
		c.NFTableName = "kube-network-policies"
	}
	return nil
}

// NewController returns a new *Controller.
func NewController(
	policyEngine *networkpolicy.PolicyEngine,
	config Config,
) (*Controller, error) {
	err := config.Defaults()
	if err != nil {
		return nil, err
	}

	return newController(
		policyEngine,
		config,
	)
}

func newController(
	policyEngine *networkpolicy.PolicyEngine,
	config Config,
) (*Controller, error) {
	klog.V(2).InfoS("Creating controller", "config", config)
	c := &Controller{
		policyEngine: policyEngine,
		config:       config,
	}
	// The runner will execute syncNFTablesRules.
	// - minInterval: Coalesce rapid changes (e.g., multiple pod updates) into a single run.
	// - retryInterval: If sync fails, retry after a short delay.
	// - maxInterval: Ensure rules are periodically resynced even if there are no events.
	c.syncRunner = runner.NewBoundedFrequencyRunner(
		controllerName,
		func() error { return c.syncNFTablesRules(context.Background()) },
		1*time.Second, // minInterval
		1*time.Second, // retryInterval
		1*time.Hour,   // maxInterval
	)

	// The sync callback now triggers the runner.
	syncCallback := func() {
		c.syncRunner.Run()
	}
	c.policyEngine.SetDataplaneSyncCallbacks(syncCallback)

	return c, nil
}

// Controller manages selector-based networkpolicy endpoints.
type Controller struct {
	config       Config
	policyEngine *networkpolicy.PolicyEngine
	syncRunner   *runner.BoundedFrequencyRunner

	nfq     *nfqueue.Nfqueue
	flushed bool
}

// Run will not return until stopCh is closed. workers determines how many
// endpoints will be handled in parallel.
func (c *Controller) Run(ctx context.Context) error {
	defer utilruntime.HandleCrash()
	logger := klog.FromContext(ctx)

	logger.Info("Starting controller", "name", controllerName)
	defer logger.Info("Shutting down controller", "name", controllerName)

	// Wait for the policy engine to be ready
	// Wait for the policy engine and all its evaluators to become ready.
	logger.Info("Waiting for the policy engine to become ready...")
	err := wait.PollUntilContextCancel(ctx, 500*time.Millisecond, true, func(context.Context) (bool, error) {
		return c.policyEngine.Ready(), nil
	})
	if err != nil {
		return fmt.Errorf("policy engine never became ready: %w", err)
	}
	logger.Info("Policy engine is ready.")

	// add metrics
	registerMetrics(ctx)
	// collect metrics periodically
	go wait.UntilWithContext(ctx, func(ctx context.Context) {
		logger := klog.FromContext(ctx)
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

	// Start the BoundedFrequencyRunner's loop.
	go c.syncRunner.Loop(ctx.Done())

	// Perform an initial sync to ensure rules are in place at startup.
	if err := c.syncNFTablesRules(ctx); err != nil {
		// Log the error but don't block startup. The runner will retry.
		logger.Error(err, "initial nftables sync failed")
	}

	var flags uint32
	// https://netfilter.org/projects/libnetfilter_queue/doxygen/html/group__Queue.html
	// the kernel will not normalize offload packets,
	// i.e. your application will need to be able to handle packets larger than the mtu.
	// Normalization is expensive, so this flag should always be set.
	// This also solves a bug with SCTP
	// https://github.com/aojea/kube-netpol/issues/8
	// https://bugzilla.netfilter.org/show_bug.cgi?id=1742
	flags = nfqueue.NfQaCfgFlagGSO
	if c.config.FailOpen {
		flags += nfqueue.NfQaCfgFlagFailOpen
	}

	// Set configuration options for nfqueue
	config := nfqueue.Config{
		NfQueue:      uint16(c.config.QueueID),
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
	defer nf.Close()

	c.nfq = nf

	// Parse the packet and check if it should be accepted
	// Packets should be evaludated independently in each direction
	fn := func(a nfqueue.Attribute) int {
		verdict := nfqueue.NfDrop
		if c.config.FailOpen {
			verdict = nfqueue.NfAccept
		}

		startTime := time.Now()
		logger.V(2).Info("Processing sync for packet", "id", *a.PacketID)

		packet, err := network.ParsePacket(*a.Payload)
		if err != nil {
			logger.Error(err, "Can not process packet, applying default policy", "id", *a.PacketID, "failOpen", c.config.FailOpen)
			c.nfq.SetVerdict(*a.PacketID, verdict) //nolint:errcheck
			return 0
		}
		packet.ID = *a.PacketID

		defer func() {
			processingTime := float64(time.Since(startTime).Microseconds())
			packetProcessingHist.WithLabelValues(string(packet.Proto), string(packet.Family)).Observe(processingTime)
			packetProcessingSum.Observe(processingTime)
			verdictStr := verdictString(verdict)
			packetCounterVec.WithLabelValues(string(packet.Proto), string(packet.Family), verdictStr).Inc()
			logger.V(2).Info("Finished syncing packet", "id", *a.PacketID, "duration", time.Since(startTime), "verdict", verdictStr)
		}()

		if c.evaluatePacket(ctx, &packet) {
			verdict = nfqueue.NfAccept
		} else {
			verdict = nfqueue.NfDrop
		}
		c.nfq.SetVerdict(*a.PacketID, verdict) //nolint:errcheck
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

	<-ctx.Done()

	return nil
}

// verifctString coverts nfqueue int vericts to strings for metrics/logging
// it does not cover all of them because we should only use a subset.
func verdictString(verdict int) string {
	switch verdict {
	case nfqueue.NfDrop:
		return "drop"
	case nfqueue.NfAccept:
		return "accept"
	default:
		return "unknown"
	}
}

// evaluatePacket evaluates the network policies by running the configured pipeline.
// The pipeline executes a series of evaluator functions in an order determined by their
// priority. Each evaluator can return a final verdict (Allow/Deny) or pass the
// packet to the next evaluator in the chain.
func (c *Controller) evaluatePacket(ctx context.Context, p *network.Packet) bool {
	allowed, err := c.policyEngine.EvaluatePacket(ctx, p)
	if err != nil {
		klog.FromContext(ctx).Error(err, "error evaluating packet")
		return c.config.FailOpen
	}
	return allowed
}

// syncNFTablesRules adds the necessary rules to process the first connection packets in userspace
// and check if network policies must apply.
// TODO: We can divert only the traffic affected by network policies using a set in nftables or an IPset.
func (c *Controller) syncNFTablesRules(ctx context.Context) error {
	klog.FromContext(ctx).Info("Syncing nftables rules")

	nft, err := nftables.New()
	if err != nil {
		return fmt.Errorf("can not start nftables:%v", err)
	}
	// add + delete + add for flushing all the table
	table := &nftables.Table{
		Name:   c.config.NFTableName,
		Family: nftables.TableFamilyINet,
	}

	nft.AddTable(table)
	nft.DelTable(table)
	nft.AddTable(table)

	allPodIPs, divertAll, err := c.policyEngine.GetManagedIPs(ctx)
	if err != nil {
		return err
	}

	if !divertAll {
		// add set with IPs impacted by network policies
		v4Set := &nftables.Set{
			Table:   table,
			Name:    podV4IPsSet,
			KeyType: nftables.TypeIPAddr,
		}
		v6Set := &nftables.Set{
			Table:   table,
			Name:    podV6IPsSet,
			KeyType: nftables.TypeIP6Addr,
		}

		var elementsV4, elementsV6 []nftables.SetElement
		for _, ip := range allPodIPs {
			if ip.Is4() {
				elementsV4 = append(elementsV4, nftables.SetElement{
					Key: ip.AsSlice(),
				})
			} else if ip.Is6() {
				elementsV6 = append(elementsV6, nftables.SetElement{
					Key: ip.AsSlice(),
				})
			}
		}

		if err := nft.AddSet(v4Set, elementsV4); err != nil {
			return fmt.Errorf("failed to add Set %s : %v", v4Set.Name, err)
		}
		if err := nft.AddSet(v6Set, elementsV6); err != nil {
			return fmt.Errorf("failed to add Set %s : %v", v6Set.Name, err)
		}
	}

	// Process the packets that are, usually on the FORWARD hook, but
	// IPVS packets follow a different path in netfilter, so we process
	// everything in the POSTROUTING hook before SNAT happens.
	// Ref: https://github.com/kubernetes-sigs/kube-network-policies/issues/46
	chain := nft.AddChain(&nftables.Chain{
		Name:     "postrouting",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityRef(*nftables.ChainPriorityNATSource - 5),
	})

	// DNS is processed by addDNSRacersWorkaroundRules()
	// TODO: remove once kernel fix is on most distros
	if c.config.NetfilterBug1766Fix {
		//  udp dport 53 accept
		nft.AddRule(&nftables.Rule{
			Table: table,
			Chain: chain,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyL4PROTO, SourceRegister: false, Register: 0x1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: []byte{unix.IPPROTO_UDP}},
				&expr.Payload{DestRegister: 0x1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: binaryutil.BigEndian.PutUint16(53)},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
		})
	}

	// IPv6 needs essential ICMP types for Neighbor Discovery to work
	// Allow essential ICMPv6 types before queue processing, but let other types
	// (like ping6) be processed by network policies
	// Ref: https://github.com/kubernetes-sigs/kube-network-policies/issues/191

	// Allow Router Solicitation (RS) - Type 133
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyNFPROTO, SourceRegister: false, Register: 0x1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: []byte{unix.NFPROTO_IPV6}},
			&expr.Meta{Key: expr.MetaKeyL4PROTO, SourceRegister: false, Register: 0x1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: []uint8{unix.IPPROTO_ICMPV6}},
			&expr.Payload{DestRegister: 0x1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: []uint8{133}},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// Allow Router Advertisement (RA) - Type 134
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyNFPROTO, SourceRegister: false, Register: 0x1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: []byte{unix.NFPROTO_IPV6}},
			&expr.Meta{Key: expr.MetaKeyL4PROTO, SourceRegister: false, Register: 0x1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: []uint8{unix.IPPROTO_ICMPV6}},
			&expr.Payload{DestRegister: 0x1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: []uint8{134}},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// Allow Neighbor Solicitation (NS) - Type 135
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyNFPROTO, SourceRegister: false, Register: 0x1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: []byte{unix.NFPROTO_IPV6}},
			&expr.Meta{Key: expr.MetaKeyL4PROTO, SourceRegister: false, Register: 0x1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: []uint8{unix.IPPROTO_ICMPV6}},
			&expr.Payload{DestRegister: 0x1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: []uint8{135}},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// Allow Neighbor Advertisement (NA) - Type 136
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyNFPROTO, SourceRegister: false, Register: 0x1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: []byte{unix.NFPROTO_IPV6}},
			&expr.Meta{Key: expr.MetaKeyL4PROTO, SourceRegister: false, Register: 0x1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: []uint8{unix.IPPROTO_ICMPV6}},
			&expr.Payload{DestRegister: 0x1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: []uint8{136}},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// Allow Neighbor Redirect - Type 137
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyNFPROTO, SourceRegister: false, Register: 0x1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: []byte{unix.NFPROTO_IPV6}},
			&expr.Meta{Key: expr.MetaKeyL4PROTO, SourceRegister: false, Register: 0x1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: []uint8{unix.IPPROTO_ICMPV6}},
			&expr.Payload{DestRegister: 0x1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: []uint8{137}},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// Don't process traffic generated from the root user in the Node, it can block kubelet probes
	// or system daemons that depend on the internal node traffic to not be blocked.
	// Ref: https://github.com/kubernetes-sigs/kube-network-policies/issues/65
	// meta skuid 0 accept
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeySKUID, SourceRegister: false, Register: 0x1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: []byte{0x0, 0x0, 0x0, 0x0}},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// ct state established,related accept
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Ct{Register: 0x1, SourceRegister: false, Key: expr.CtKeySTATE},
			&expr.Bitwise{SourceRegister: 0x1, DestRegister: 0x1, Len: 0x4, Mask: binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED), Xor: []byte{0x0, 0x0, 0x0, 0x0}},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 0x1, Data: []byte{0x0, 0x0, 0x0, 0x0}},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	queue := &expr.Queue{Num: uint16(c.config.QueueID)}
	if c.config.FailOpen {
		queue.Flag = expr.QueueFlagBypass
	}

	// only if no admin network policies are used
	if !divertAll {
		// ip saddr @podips-v4 queue flags bypass to 102
		nft.AddRule(&nftables.Rule{
			Table: table,
			Chain: chain,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyNFPROTO, SourceRegister: false, Register: 0x1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: []uint8{unix.NFPROTO_IPV4}},
				&expr.Payload{DestRegister: 0x1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
				&expr.Lookup{SourceRegister: 0x1, DestRegister: 0x0, SetName: "podips-v4"},
				queue,
			},
		})
		// ip daddr @podips-v4 queue flags bypass to 102
		nft.AddRule(&nftables.Rule{
			Table: table,
			Chain: chain,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyNFPROTO, SourceRegister: false, Register: 0x1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: []uint8{unix.NFPROTO_IPV4}},
				&expr.Payload{DestRegister: 0x1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
				&expr.Lookup{SourceRegister: 0x1, DestRegister: 0x0, SetName: "podips-v4"},
				queue,
			},
		})
		// ip6 saddr @podips-v6 queue flags bypass to 102
		nft.AddRule(&nftables.Rule{
			Table: table,
			Chain: chain,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyNFPROTO, SourceRegister: false, Register: 0x1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: []uint8{unix.NFPROTO_IPV6}},
				&expr.Payload{DestRegister: 0x1, Base: expr.PayloadBaseNetworkHeader, Offset: 8, Len: 16},
				&expr.Lookup{SourceRegister: 0x1, DestRegister: 0x0, SetName: "podips-v6"},
				queue,
			},
		})
		// ip6 daddr @podips-v6 queue flags bypass to 102
		nft.AddRule(&nftables.Rule{
			Table: table,
			Chain: chain,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyNFPROTO, SourceRegister: false, Register: 0x1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: []uint8{unix.NFPROTO_IPV6}},
				&expr.Payload{DestRegister: 0x1, Base: expr.PayloadBaseNetworkHeader, Offset: 24, Len: 16},
				&expr.Lookup{SourceRegister: 0x1, DestRegister: 0x0, SetName: "podips-v6"},
				queue,
			},
		})
	} else {
		nft.AddRule(&nftables.Rule{
			Table: table,
			Chain: chain,
			Exprs: []expr.Any{
				queue,
			},
		})
	}

	if c.config.NetfilterBug1766Fix {
		c.addDNSRacersWorkaroundRules(nft, table, divertAll)
	}

	if err := nft.Flush(); err != nil {
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
func (c *Controller) addDNSRacersWorkaroundRules(nft *nftables.Conn, table *nftables.Table, divertAll bool) {
	chain := nft.AddChain(&nftables.Chain{
		Name:     "prerouting",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityRef(*nftables.ChainPriorityNATDest + 5),
	})

	// meta l4proto != udp
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, SourceRegister: false, Register: 0x1},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 0x1, Data: []byte{unix.IPPROTO_UDP}},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})
	// udp dport != 53 accept
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, SourceRegister: false, Register: 0x1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: []byte{unix.IPPROTO_UDP}},
			&expr.Payload{DestRegister: 0x1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 0x1, Data: binaryutil.BigEndian.PutUint16(53)},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	queue := &expr.Queue{Num: uint16(c.config.QueueID)}
	if c.config.FailOpen {
		queue.Flag = expr.QueueFlagBypass
	}

	// only if no admin network policies are used
	if !divertAll {
		// ip saddr @podips-v4 queue flags bypass to 102
		nft.AddRule(&nftables.Rule{
			Table: table,
			Chain: chain,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyNFPROTO, SourceRegister: false, Register: 0x1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: []uint8{unix.NFPROTO_IPV4}},
				&expr.Payload{DestRegister: 0x1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
				&expr.Lookup{SourceRegister: 0x1, DestRegister: 0x0, SetName: "podips-v4"},
				queue,
			},
		})
		nft.AddRule(&nftables.Rule{
			Table: table,
			Chain: chain,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyNFPROTO, SourceRegister: false, Register: 0x1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: []uint8{unix.NFPROTO_IPV4}},
				&expr.Payload{DestRegister: 0x1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
				&expr.Lookup{SourceRegister: 0x1, DestRegister: 0x0, SetName: "podips-v4"},
				queue,
			},
		})
		nft.AddRule(&nftables.Rule{
			Table: table,
			Chain: chain,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyNFPROTO, SourceRegister: false, Register: 0x1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: []uint8{unix.NFPROTO_IPV6}},
				&expr.Payload{DestRegister: 0x1, Base: expr.PayloadBaseNetworkHeader, Offset: 8, Len: 16},
				&expr.Lookup{SourceRegister: 0x1, DestRegister: 0x0, SetName: "podips-v6"},
				queue,
			},
		})
		nft.AddRule(&nftables.Rule{
			Table: table,
			Chain: chain,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyNFPROTO, SourceRegister: false, Register: 0x1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: []uint8{unix.NFPROTO_IPV6}},
				&expr.Payload{DestRegister: 0x1, Base: expr.PayloadBaseNetworkHeader, Offset: 24, Len: 16},
				&expr.Lookup{SourceRegister: 0x1, DestRegister: 0x0, SetName: "podips-v6"},
				queue,
			},
		})
	} else {
		nft.AddRule(&nftables.Rule{
			Table: table,
			Chain: chain,
			Exprs: []expr.Any{
				queue,
			},
		})
	}
}

func (c *Controller) cleanNFTablesRules(ctx context.Context) {
	klog.Infof("cleaning up nftable %s", c.config.NFTableName)
	nft, err := nftables.New()
	if err != nil {
		klog.Infof("network policies cleanup failure, can not start nftables:%v", err)
		return
	}
	// Add+Delete is idempotent and won't return an error if the table doesn't already
	// exist.
	table := &nftables.Table{
		Name:   c.config.NFTableName,
		Family: nftables.TableFamilyINet,
	}
	nft.DelTable(table)

	err = nft.Flush()
	if err != nil {
		klog.Infof("error deleting nftables rules %v", err)
	}
	klog.Infof("cleaned up nftable %s", c.config.NFTableName)
}
