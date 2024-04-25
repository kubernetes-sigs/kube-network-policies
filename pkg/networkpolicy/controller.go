package networkpolicy

import (
	"context"
	"fmt"
	"time"

	nfqueue "github.com/florianl/go-nfqueue"
	"github.com/mdlayher/netlink"

	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	networkinginformers "k8s.io/client-go/informers/networking/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	v1core "k8s.io/client-go/kubernetes/typed/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	networkinglisters "k8s.io/client-go/listers/networking/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog/v2"

	"sigs.k8s.io/knftables"
	npav1alpha1 "sigs.k8s.io/network-policy-api/apis/v1alpha1"
	npaclient "sigs.k8s.io/network-policy-api/pkg/client/clientset/versioned"
	policyinformers "sigs.k8s.io/network-policy-api/pkg/client/informers/externalversions/apis/v1alpha1"
	policylisters "sigs.k8s.io/network-policy-api/pkg/client/listers/apis/v1alpha1"
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
)

type Config struct {
	FailOpen                   bool // allow traffic if the controller is not available
	AdminNetworkPolicy         bool
	BaselineAdminNetworkPolicy bool
	QueueID                    int
}

// NewController returns a new *Controller.
func NewController(client clientset.Interface,
	nft knftables.Interface,
	networkpolicyInformer networkinginformers.NetworkPolicyInformer,
	namespaceInformer coreinformers.NamespaceInformer,
	podInformer coreinformers.PodInformer,
	nodeInformer coreinformers.NodeInformer,
	npaClient npaclient.Interface,
	adminNetworkPolicyInformer policyinformers.AdminNetworkPolicyInformer,
	baselineAdminNetworkPolicyInformer policyinformers.BaselineAdminNetworkPolicyInformer,
	config Config,
) *Controller {
	klog.V(2).Info("Creating event broadcaster")
	broadcaster := record.NewBroadcaster()
	broadcaster.StartStructuredLogging(0)
	broadcaster.StartRecordingToSink(&v1core.EventSinkImpl{Interface: client.CoreV1().Events("")})
	recorder := broadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: controllerName})

	klog.V(2).Infof("Creating controller: %#v", config)
	c := &Controller{
		client: client,
		config: config,
		nft:    nft,
	}

	err := podInformer.Informer().AddIndexers(cache.Indexers{
		podIPIndex: func(obj interface{}) ([]string, error) {
			pod, ok := obj.(*v1.Pod)
			if !ok {
				return []string{}, nil
			}
			// TODO check this later or it can block some traffic
			// unrelated to the Pod
			if pod.Spec.HostNetwork {
				return []string{}, nil
			}
			result := []string{}
			for _, ip := range pod.Status.PodIPs {
				result = append(result, string(ip.IP))
			}
			return result, nil
		},
	})
	if err != nil {
		panic(err)
	}

	podIndexer := podInformer.Informer().GetIndexer()
	// Theoretically only one IP can be active at a time
	c.getPodAssignedToIP = func(podIP string) *v1.Pod {
		objs, err := podIndexer.ByIndex(podIPIndex, podIP)
		if err != nil {
			return nil
		}
		if len(objs) == 0 {
			return nil
		}
		// if there are multiple pods use the one that is running
		for _, obj := range objs {
			pod, ok := obj.(*v1.Pod)
			if !ok {
				continue
			}
			if pod.Status.Phase == v1.PodRunning {
				return pod
			}
		}
		// if no pod is running pick the first one
		// TODO: check multiple phases
		return objs[0].(*v1.Pod)
	}

	// reduce memory usage only care about Labels and Status
	trim := func(obj interface{}) (interface{}, error) {
		if accessor, err := meta.Accessor(obj); err == nil {
			accessor.SetManagedFields(nil)
		}
		return obj, nil
	}
	err = podInformer.Informer().SetTransform(trim)
	if err != nil {
		utilruntime.HandleError(err)
	}

	c.podLister = podInformer.Lister()
	c.podsSynced = podInformer.Informer().HasSynced
	c.namespaceLister = namespaceInformer.Lister()
	c.namespacesSynced = namespaceInformer.Informer().HasSynced
	c.networkpolicyLister = networkpolicyInformer.Lister()
	c.networkpoliciesSynced = networkpolicyInformer.Informer().HasSynced
	if config.AdminNetworkPolicy || config.BaselineAdminNetworkPolicy {
		c.npaClient = npaClient
		c.nodeLister = nodeInformer.Lister()
		c.nodesSynced = nodeInformer.Informer().HasSynced
	}

	if config.AdminNetworkPolicy {
		c.adminNetworkPolicyLister = adminNetworkPolicyInformer.Lister()
		c.adminNetworkPolicySynced = adminNetworkPolicyInformer.Informer().HasSynced
	}

	if config.BaselineAdminNetworkPolicy {
		c.baselineAdminNetworkPolicyLister = baselineAdminNetworkPolicyInformer.Lister()
		c.baselineAdminNetworkPolicySynced = baselineAdminNetworkPolicyInformer.Informer().HasSynced
	}

	c.eventBroadcaster = broadcaster
	c.eventRecorder = recorder

	return c
}

// Controller manages selector-based networkpolicy endpoints.
type Controller struct {
	config Config

	client           clientset.Interface
	eventBroadcaster record.EventBroadcaster
	eventRecorder    record.EventRecorder

	// informers for network policies, namespaces and pods
	networkpolicyLister   networkinglisters.NetworkPolicyLister
	networkpoliciesSynced cache.InformerSynced
	namespaceLister       corelisters.NamespaceLister
	namespacesSynced      cache.InformerSynced
	podLister             corelisters.PodLister
	podsSynced            cache.InformerSynced

	npaClient npaclient.Interface

	adminNetworkPolicyLister         policylisters.AdminNetworkPolicyLister
	adminNetworkPolicySynced         cache.InformerSynced
	baselineAdminNetworkPolicyLister policylisters.BaselineAdminNetworkPolicyLister
	baselineAdminNetworkPolicySynced cache.InformerSynced
	nodeLister                       corelisters.NodeLister
	nodesSynced                      cache.InformerSynced
	// function to get the Pod given an IP
	// if an error or not found it returns nil
	getPodAssignedToIP func(podIP string) *v1.Pod

	nft     knftables.Interface // install the necessary nftables rules
	nfq     *nfqueue.Nfqueue
	flushed bool
}

// Run will not return until stopCh is closed. workers determines how many
// endpoints will be handled in parallel.
func (c *Controller) Run(ctx context.Context) error {
	defer utilruntime.HandleCrash()

	klog.Infof("Starting controller %s", controllerName)
	defer klog.Infof("Shutting down controller %s", controllerName)

	// Wait for the caches to be synced
	klog.Info("Waiting for informer caches to sync")
	caches := []cache.InformerSynced{c.networkpoliciesSynced, c.namespacesSynced, c.podsSynced}
	if c.config.AdminNetworkPolicy || c.config.BaselineAdminNetworkPolicy {
		caches = append(caches, c.nodesSynced)
	}
	if c.config.AdminNetworkPolicy {
		caches = append(caches, c.adminNetworkPolicySynced)
	}
	if c.config.BaselineAdminNetworkPolicy {
		caches = append(caches, c.baselineAdminNetworkPolicySynced)
	}
	if !cache.WaitForNamedCacheSync(controllerName, ctx.Done(), caches...) {
		return fmt.Errorf("error syncing cache")
	}

	// add metrics
	registerMetrics(ctx)
	// collect metrics periodically
	go wait.UntilWithContext(ctx, func(ctx context.Context) {
		queues, err := readNfnetlinkQueueStats()
		if err != nil {
			klog.Infof("error reading nfqueue stats: %v", err)
			return
		}
		klog.V(4).Infof("Obtained metrics for %d queues", len(queues))
		for _, q := range queues {
			klog.V(4).Infof("Updating metrics for queue: %d", q.id_sequence)
			nfqueueQueueTotal.WithLabelValues(q.queue_number).Set(float64(q.queue_total))
			nfqueueQueueDropped.WithLabelValues(q.queue_number).Set(float64(q.queue_dropped))
			nfqueueUserDropped.WithLabelValues(q.queue_number).Set(float64(q.user_dropped))
			nfqueuePacketID.WithLabelValues(q.queue_number).Set(float64(q.id_sequence))
		}

	}, 30*time.Second)

	// Start the workers after the repair loop to avoid races
	klog.Info("Syncing nftables rules")
	c.syncNFTablesRules(ctx)
	defer c.cleanNFTablesRules()
	// FIXME: there should be no need to ever resync our rules, but if we're going to
	// do that, then knftables should provide us with an API to tell us when we need
	// to resync (using `nft monitor` or direct netlink), rather than us polling.
	go wait.Until(func() { c.syncNFTablesRules(ctx) }, 60*time.Second, ctx.Done())

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
		klog.Infof("could not open nfqueue socket: %v", err)
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
		klog.V(2).Infof("Processing sync for packet %d", *a.PacketID)

		packet, err := parsePacket(*a.Payload)
		if err != nil {
			klog.Infof("Can not process packet %d applying default policy (failOpen: %v): %v", *a.PacketID, c.config.FailOpen, err)
			c.nfq.SetVerdict(*a.PacketID, verdict) //nolint:errcheck
			return 0
		}
		packet.id = *a.PacketID

		defer func() {
			processingTime := float64(time.Since(startTime).Microseconds())
			packetProcessingHist.WithLabelValues(string(packet.proto), string(packet.family)).Observe(processingTime)
			packetProcessingSum.Observe(processingTime)
			packetCounterVec.WithLabelValues(string(packet.proto), string(packet.family)).Inc()
			klog.V(2).Infof("Finished syncing packet %d took: %v accepted: %v", *a.PacketID, time.Since(startTime), verdict == nfqueue.NfAccept)
		}()

		if c.evaluatePacket(packet) {
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
		klog.Infof("Could not receive message: %v\n", err)
		return 0
	})
	if err != nil {
		klog.Infof("could not open nfqueue socket: %v", err)
		return err
	}

	<-ctx.Done()

	return nil
}

// evaluatePacket evalute the network policies using the following order:
// 1. AdminNetworkPolicies in Egress for the source Pod/IP
// 2. NetworkPolicies in Egress (if needed) for the source Pod/IP
// 3. BaselineAdminNetworkPolicies in Egress (if needed) for the source Pod/IP
// 4. AdminNetworkPolicies in Ingress for the destination Pod/IP
// 5. NetworkPolicies in Ingress (if needed) for the destination Pod/IP
// 6. BaselineAdminNetworkPolicies in Ingress (if needed) for the destination Pod/IP
func (c *Controller) evaluatePacket(p packet) bool {
	srcIP := p.srcIP
	srcPod := c.getPodAssignedToIP(srcIP.String())
	srcPort := p.srcPort
	dstIP := p.dstIP
	dstPod := c.getPodAssignedToIP(dstIP.String())
	dstPort := p.dstPort
	protocol := p.proto

	klog.V(2).Infof("Evaluating packet %s", p.String())

	// Evalute Egress Policies

	// Admin Network Policies are evaluated first
	evaluateEgressNetworkPolicy := true
	if c.config.AdminNetworkPolicy {
		srcPodAdminNetworkPolices := c.getAdminNetworkPoliciesForPod(srcPod)
		action := c.evaluateAdminEgress(srcPodAdminNetworkPolices, dstPod, dstIP, dstPort, protocol)
		klog.V(2).Infof("[Packet %d] Egress AdminNetworkPolicies: %d Action: %s", p.id, len(srcPodAdminNetworkPolices), action)
		switch action {
		case npav1alpha1.AdminNetworkPolicyRuleActionDeny: // Deny the packet no need to check anything else
			return false
		case npav1alpha1.AdminNetworkPolicyRuleActionAllow: // Packet is allowed in Egress so no need to evalute Network Policies
			evaluateEgressNetworkPolicy = false
		case npav1alpha1.AdminNetworkPolicyRuleActionPass: // Packet need to evalute Egress Network Policies
		}
	}
	evaluateAdminEgressNetworkPolicy := evaluateEgressNetworkPolicy
	if evaluateEgressNetworkPolicy {
		srcPodNetworkPolices := c.getNetworkPoliciesForPod(srcPod)
		if len(srcPodNetworkPolices) > 0 {
			evaluateAdminEgressNetworkPolicy = false
		}
		allowed := c.evaluator(srcPodNetworkPolices, networkingv1.PolicyTypeEgress, srcPod, srcPort, dstPod, dstIP, dstPort, protocol)
		klog.V(2).Infof("[Packet %d] Egress NetworkPolicies: %d Allowed: %v", p.id, len(srcPodNetworkPolices), allowed)
		if !allowed {
			return false
		}
	}
	if c.config.BaselineAdminNetworkPolicy && evaluateAdminEgressNetworkPolicy {
		srcPodBaselineAdminNetworkPolices := c.getBaselineAdminNetworkPoliciesForPod(srcPod)
		action := c.evaluateBaselineAdminEgress(srcPodBaselineAdminNetworkPolices, dstPod, dstIP, dstPort, protocol)
		klog.V(2).Infof("[Packet %d] Egress BaselineAdminNetworkPolicies: %d Action: %s", p.id, len(srcPodBaselineAdminNetworkPolices), action)
		switch action {
		case npav1alpha1.BaselineAdminNetworkPolicyRuleActionDeny: // Deny the packet no need to check anything else
			return false
		case npav1alpha1.BaselineAdminNetworkPolicyRuleActionAllow:
		}
	}

	// Evalute Ingress Policies

	// Admin Network Policies are evaluated first
	if c.config.AdminNetworkPolicy {
		dstPodAdminNetworkPolices := c.getAdminNetworkPoliciesForPod(dstPod)
		action := c.evaluateAdminIngress(dstPodAdminNetworkPolices, srcPod, dstPort, protocol)
		klog.V(2).Infof("[Packet %d] Ingress AdminNetworkPolicies: %d Action: %s", p.id, len(dstPodAdminNetworkPolices), action)
		switch action {
		case npav1alpha1.AdminNetworkPolicyRuleActionDeny: // Deny the packet no need to check anything else
			return false
		case npav1alpha1.AdminNetworkPolicyRuleActionAllow: // Packet is allowed in Egress so no need to evalute Network Policies
			return true
		case npav1alpha1.AdminNetworkPolicyRuleActionPass: // Packet need to evalute Egress Network Policies
		}
	}
	// Network policies override Baseline Admin Network Policies
	dstPodNetworkPolices := c.getNetworkPoliciesForPod(dstPod)
	if len(dstPodNetworkPolices) > 0 {
		allowed := c.evaluator(dstPodNetworkPolices, networkingv1.PolicyTypeIngress, dstPod, dstPort, srcPod, srcIP, srcPort, protocol)
		klog.V(2).Infof("[Packet %d] Egress NetworkPolicies: %d Allowed: %v", p.id, len(dstPodNetworkPolices), allowed)
		return allowed
	}
	if c.config.BaselineAdminNetworkPolicy {
		dstPodBaselineAdminNetworkPolices := c.getBaselineAdminNetworkPoliciesForPod(dstPod)
		action := c.evaluateBaselineAdminIngress(dstPodBaselineAdminNetworkPolices, srcPod, dstPort, protocol)
		klog.V(2).Infof("[Packet %d] Egress BaselineAdminNetworkPolicies: %d Action: %s", p.id, len(dstPodBaselineAdminNetworkPolices), action)
		switch action {
		case npav1alpha1.BaselineAdminNetworkPolicyRuleActionDeny: // Deny the packet no need to check anything else
			return false
		case npav1alpha1.BaselineAdminNetworkPolicyRuleActionAllow:
			return true
		}
	}
	return true
}

// syncNFTablesRules adds the necessary rules to process the first connection packets in userspace
// and check if network policies must apply.
// TODO: We can divert only the traffic affected by network policies using a set in nftables or an IPset.
func (c *Controller) syncNFTablesRules(ctx context.Context) {
	rule := fmt.Sprintf("ct state new queue to %d", c.config.QueueID)
	if c.config.FailOpen {
		rule += " bypass"
	}
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

	for _, hook := range []knftables.BaseChainHook{knftables.ForwardHook} {
		chainName := string(hook)
		tx.Add(&knftables.Chain{
			Name:     chainName,
			Type:     knftables.PtrTo(knftables.FilterType),
			Hook:     knftables.PtrTo(hook),
			Priority: knftables.PtrTo(knftables.FilterPriority + "-5"),
		})
		tx.Flush(&knftables.Chain{
			Name: chainName,
		})
		tx.Add(&knftables.Rule{
			Chain: chainName,
			Rule:  rule,
		})
	}

	if err := c.nft.Run(ctx, tx); err != nil {
		klog.Infof("error syncing nftables rules %v", err)
	}
}

func (c *Controller) cleanNFTablesRules() {
	tx := c.nft.NewTransaction()
	// Add+Delete is idempotent and won't return an error if the table doesn't already
	// exist.
	tx.Add(&knftables.Table{})
	tx.Delete(&knftables.Table{})

	if err := c.nft.Run(context.TODO(), tx); err != nil {
		klog.Infof("error deleting nftables rules %v", err)
	}
}
