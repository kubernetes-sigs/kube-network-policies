package dataplane

import (
	"context"
	"errors"
	"fmt"
	"time"

	nfqueue "github.com/florianl/go-nfqueue/v2"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	vishnetlink "github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
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
	StrictMode          bool   // enforce network policies also on established connections
	CTLabelAccept       int    // conntrack label to set on accepted connections (between 1-127)
}

func (c *Config) Defaults() error {
	if c.QueueID == 0 {
		c.QueueID = 100
	}

	if c.NFTableName == "" {
		c.NFTableName = "kube-network-policies"
	}
	if c.CTLabelAccept == 0 {
		c.CTLabelAccept = 100
	}

	return nil
}

func (c *Config) Validate() error {
	var errorsList []error
	if c.QueueID < 0 {
		errorsList = append(errorsList, fmt.Errorf("invalid queue id"))
	}

	if c.CTLabelAccept < 0 || c.CTLabelAccept > 127 {
		errorsList = append(errorsList, fmt.Errorf("invalid ct label accept value, must be between 1-127"))
	}

	return errors.Join(errorsList...)
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

	err = config.Validate()
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

	if c.config.StrictMode {
		// The runner will explore existing connections listed on the conntrack table
		// and timeout the conntrack entries of the no longer valid connections to reenqueue
		// the packets and enforce network policies.
		c.connRunner = runner.NewBoundedFrequencyRunner(
			controllerName+"-firewall-enforcer",
			func() error { return c.firewallEnforcer(context.Background()) },
			30*time.Second, // minInterval (less frequent than nftables sync to avoid overload listing conntrack entries)
			15*time.Second, // retryInterval
			1*time.Hour,    // maxInterval
		)
	}

	// The sync callback now triggers the runner.
	syncCallback := func() {
		c.syncRunner.Run()
		if c.config.StrictMode {
			c.connRunner.Run()
		}
	}
	c.policyEngine.SetDataplaneSyncCallbacks(syncCallback)

	return c, nil
}

// Controller manages selector-based networkpolicy endpoints.
type Controller struct {
	config       Config
	policyEngine *networkpolicy.PolicyEngine
	syncRunner   *runner.BoundedFrequencyRunner
	connRunner   *runner.BoundedFrequencyRunner

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
		logger := klog.FromContext(ctx).WithName("metrics-collector")
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

	// Start the BoundedFrequencyRunner's loops.
	go c.syncRunner.Loop(ctx.Done())
	if c.config.StrictMode {
		go c.connRunner.Loop(ctx.Done())
	}

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

		var verdictError error
		if c.evaluatePacket(ctx, &packet) {
			verdict = nfqueue.NfAccept
			// TODO: it is unclear if setting the label here will completely remove the existing labels
			// or just set the specific bit. If it removes all the existing labels we need to read them first.
			// Based on the bugs found in the conntrack and netfilter code around ct labels, it is likely that
			// it removes all existing labels, but also that is not widely used, so for now we set it directly.
			verdictError = c.nfq.SetVerdictWithLabel(*a.PacketID, verdict, generateLabelMask(c.config.CTLabelAccept))
		} else {
			verdict = nfqueue.NfDrop
			verdictError = c.nfq.SetVerdict(*a.PacketID, verdict)
		}
		if verdictError != nil {
			logger.Error(verdictError, "failed to set verdict with label", "id", *a.PacketID)
		}
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

	c.Shutdown(context.Background())

	return nil
}

// Shutdown handles graceful shutdown of the controller.
func (c *Controller) Shutdown(ctx context.Context) {
	klog.Info("Shutting down controller logic")

	// On shutdown, we need to decide whether to clean up nftables rules.
	// - If we clean up, there's a traffic gap during upgrades.
	// - If we don't clean up, we might blackhole traffic on uninstall if FailOpen is false.

	// If FailOpen is true, we can safely leave the rules. The 'bypass' flag
	// on the nfqueue rule will allow traffic to pass through if the controller
	// is not running. The new controller instance will sync the rules.
	// This avoids service disruption during upgrades.
	if c.config.FailOpen {
		klog.Info("FailOpen is true, skipping nftables cleanup on shutdown to avoid traffic disruption.")
		return
	}

	// If FailOpen is false, the priority is to not let traffic pass when the
	// controller is not running. Leaving the rules would cause the kernel to drop
	// packets queued to a non-existent process, effectively blackholing traffic.
	// Therefore, we must clean up the rules.
	klog.Info("FailOpen is false, cleaning up nftables rules on shutdown.")
	c.cleanNFTablesRules(ctx)
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

// firewallEnforcer retrieves conntrack entries and enforces current network policies on them
// by flushing the conntrack entries that are not allowed anymore so they are
// processed again in the queue.
func (c *Controller) firewallEnforcer(ctx context.Context) error {
	var errorList []error
	logger := klog.FromContext(ctx).WithName("firewall-enforcer")
	logger.Info("Enforcing firewall policies on existing connections")

	start := time.Now()

	flows, err := vishnetlink.ConntrackTableList(vishnetlink.ConntrackTable, vishnetlink.FAMILY_ALL)
	if err != nil {
		logger.Error(err, "listing conntrack entries")
		return err
	}

	defer func() {
		logger.Info("Completed enforcing firewall policies on existing connections", "nflows", len(flows), "elapsed", time.Since(start))
	}()

	allPodIPs, divertAll, err := c.policyEngine.GetManagedIPs(ctx)
	if err != nil {
		logger.Error(err, "getting managed IPs for firewall enforcement")
		return err
	}

	ipset := sets.Set[string]{}
	if !divertAll {
		for _, ip := range allPodIPs {
			ipset.Insert(ip.String())
		}
	}

	for _, flow := range flows {
		// only UDP, SCTP or TCP connections in ESTABLISHED state are evaluated
		if flow.Forward.Protocol != unix.IPPROTO_UDP &&
			flow.Forward.Protocol != unix.IPPROTO_SCTP &&
			flow.Forward.Protocol != unix.IPPROTO_TCP {
			continue
		}
		if flow.ProtoInfo != nil {
			if state, ok := flow.ProtoInfo.(*vishnetlink.ProtoInfoTCP); ok && state.State != nl.TCP_CONNTRACK_ESTABLISHED {
				continue
			}
		}

		// If divertAll is true, all pod IPs are managed by network policies.
		// Otherwise, checks the source IP of the forward flow and the translated IP of the reverse flow,
		// as these are the IPs that belong to the pods in case of DNAT for Services.
		if !divertAll {
			if !ipset.Has(flow.Forward.SrcIP.String()) && !ipset.Has(flow.Reverse.SrcIP.String()) {
				logger.V(4).Info("Skipping conntrack entry not involving managed IPs", "flow", flow)
				continue
			}
		}

		// The policy engine evaluates packets, so we need to convert the conntrack flow to a packet.
		// The packet is evaluated against the current network policies both for source and destination.
		packet := PacketFromFlow(flow)
		if packet == nil {
			continue
		}
		logger.V(4).Info("Evaluating packet", "packet", packet.String())

		// Evaluate the packet against current network policies.
		allowed, err := c.policyEngine.EvaluatePacket(ctx, packet)
		if err != nil {
			logger.Info("error evaluating conntrack entry", "flow", flow, "err", err)
			continue
		}

		if !allowed {
			logger.V(4).Info("Connection no longer allowed by network policies", "packet", packet.String())
			// clear label so it can be re-evaluated in the queue
			flow.Labels = clearLabelBit(flow.Labels, c.config.CTLabelAccept)
			err = vishnetlink.ConntrackUpdate(vishnetlink.ConntrackTable, vishnetlink.InetFamily(flow.FamilyType), flow)
			if err != nil {
				errorList = append(errorList, err)
			}
		}
	}

	return errors.Join(errorList...)
}

// syncNFTablesRules adds the necessary rules to process the first connection packets in userspace
// and check if network policies must apply.
// TODO: We can divert only the traffic affected by network policies using a set in nftables or an IPset.
func (c *Controller) syncNFTablesRules(ctx context.Context) error {
	logger := klog.FromContext(ctx).WithName("nftables-sync")

	logger.Info("Syncing nftables rules")
	start := time.Now()
	defer func() {
		logger.Info("Syncing nftables rules", "elapsed", time.Since(start))
	}()

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
			&expr.Counter{},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// The queue sets the conntrack mark for the packets it processes,
	// so we can clear the mark here later to re-process connections if needed.
	// ct label X state established,related accept
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Ct{Register: 0x1, Key: expr.CtKeyLABELS},
			&expr.Bitwise{SourceRegister: 0x1, DestRegister: 0x1, Len: 16, Mask: generateLabelMask(c.config.CTLabelAccept), Xor: make([]byte, 16)},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 0x1, Data: make([]byte, 16)},
			&expr.Ct{Register: 0x1, Key: expr.CtKeySTATE},
			&expr.Bitwise{SourceRegister: 0x1, DestRegister: 0x1, Len: 0x4, Mask: binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED), Xor: []byte{0x0, 0x0, 0x0, 0x0}},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 0x1, Data: []byte{0x0, 0x0, 0x0, 0x0}},
			&expr.Counter{},
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

	// There has to be a "fake" entry to set labels in order to enable the ct label extension mechanism,
	// This entry will only match if the queue is bypassed and the packet is accepted in that case.
	// The entry is needed because otherwise netlink operations to set the conntrack labels will fail with ENOSPC
	// see https://patchwork.ozlabs.org/project/netfilter-devel/patch/20251020200805.298670-1-aojea@google.com/
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Immediate{Register: 0x1, Data: generateLabelMask(c.config.CTLabelAccept)},
			&expr.Ct{Register: 0x1, SourceRegister: true, Key: expr.CtKeyLABELS},
		},
	})

	if c.config.NetfilterBug1766Fix {
		c.addDNSRacersWorkaroundRules(nft, table, divertAll)
	}

	if err := nft.Flush(); err != nil {
		logger.Info("syncing nftables rules", "error", err)
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
