package networkpolicy

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"time"

	nfqueue "github.com/florianl/go-nfqueue"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"

	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/labels"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
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
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
	netutils "k8s.io/utils/net"

	"sigs.k8s.io/kube-network-policies/pkg/network"
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
	syncKey        = "dummy-key" // use the same key to sync to aggregate the events
	podV4IPsSet    = "podips-v4"
	podV6IPsSet    = "podips-v6"
)

type Config struct {
	FailOpen                   bool // allow traffic if the controller is not available
	AdminNetworkPolicy         bool
	BaselineAdminNetworkPolicy bool
	QueueID                    int
	NodeName                   string
	NetfilterBug1766Fix        bool
	NFTableName                string // if other projects use this controllers they need to be able to use their own table name
	NRIdisabled                bool   // use NRI to get the Pod IPs information locally instead of waiting to be published by the apiserver
}

func (c *Config) Defaults() error {
	var err error
	if c.QueueID == 0 {
		c.QueueID = 100
	}
	if c.NodeName == "" {
		c.NodeName, err = os.Hostname()
		if err != nil {
			return err
		}
	}
	if c.NFTableName == "" {
		c.NFTableName = "kube-network-policies"
	}
	return nil
}

// NewController returns a new *Controller.
func NewController(client clientset.Interface,
	networkpolicyInformer networkinginformers.NetworkPolicyInformer,
	namespaceInformer coreinformers.NamespaceInformer,
	podInformer coreinformers.PodInformer,
	nodeInformer coreinformers.NodeInformer,
	npaClient npaclient.Interface,
	adminNetworkPolicyInformer policyinformers.AdminNetworkPolicyInformer,
	baselineAdminNetworkPolicyInformer policyinformers.BaselineAdminNetworkPolicyInformer,
	config Config,
) (*Controller, error) {
	err := config.Defaults()
	if err != nil {
		return nil, err
	}

	return newController(
		client,
		networkpolicyInformer,
		namespaceInformer,
		podInformer,
		nodeInformer,
		npaClient,
		adminNetworkPolicyInformer,
		baselineAdminNetworkPolicyInformer,
		config,
	)
}

func newController(client clientset.Interface,
	networkpolicyInformer networkinginformers.NetworkPolicyInformer,
	namespaceInformer coreinformers.NamespaceInformer,
	podInformer coreinformers.PodInformer,
	nodeInformer coreinformers.NodeInformer,
	npaClient npaclient.Interface,
	adminNetworkPolicyInformer policyinformers.AdminNetworkPolicyInformer,
	baselineAdminNetworkPolicyInformer policyinformers.BaselineAdminNetworkPolicyInformer,
	config Config,
) (*Controller, error) {
	klog.V(2).Info("Creating event broadcaster")
	broadcaster := record.NewBroadcaster()
	broadcaster.StartStructuredLogging(0)
	broadcaster.StartRecordingToSink(&v1core.EventSinkImpl{Interface: client.CoreV1().Events("")})
	recorder := broadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: controllerName})

	klog.V(2).InfoS("Creating controller", "config", config)
	c := &Controller{
		client: client,
		config: config,
		queue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.DefaultTypedControllerRateLimiter[string](),
			workqueue.TypedRateLimitingQueueConfig[string]{Name: controllerName},
		),
	}

	if !config.NRIdisabled {
		nriPlugin, err := NewNriPlugin()
		if err != nil {
			klog.Infof("failed to create NRI plugin, using apiserver information only: %v", err)
		} else {
			c.nriPlugin = nriPlugin
		}
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
		return nil, err
	}

	podIndexer := podInformer.Informer().GetIndexer()
	// Theoretically only one IP can be active at a time
	c.getPodAssignedToIP = func(podIP string) *v1.Pod {
		objs, err := podIndexer.ByIndex(podIPIndex, podIP)
		if err != nil {
			return nil
		}
		// check if we have the local information from nri
		if len(objs) == 0 {
			podKey := c.nriPlugin.GetPodFromIP(podIP)
			obj, ok, err := podIndexer.GetByKey(podKey)
			if err != nil || !ok {
				return nil
			}
			return obj.(*v1.Pod)
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
		return nil, err
	}

	// process only local Pods that are affected by network policices
	_, _ = podInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod := obj.(*v1.Pod)
			if pod.Spec.NodeName != c.config.NodeName {
				return
			}
			if len(c.getNetworkPoliciesForPod(pod)) > 0 {
				c.queue.Add(syncKey)
			}
		},
		UpdateFunc: func(old, cur interface{}) {
			pod := cur.(*v1.Pod)
			if pod.Spec.NodeName != c.config.NodeName {
				return
			}
			if len(c.getNetworkPoliciesForPod(pod)) > 0 {
				c.queue.Add(syncKey)
			}
		},
		DeleteFunc: func(obj interface{}) {
			pod, ok := obj.(*v1.Pod)
			if !ok {
				// If we reached here it means the pod was deleted but its final state is unrecorded.
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					utilruntime.HandleError(fmt.Errorf("couldn't get object from tombstone %#v", obj))
					return
				}
				pod, ok = tombstone.Obj.(*v1.Pod)
				if !ok {
					utilruntime.HandleError(fmt.Errorf("tombstone contained object that is not a Pod: %#v", obj))
					return
				}
			}
			if pod.Spec.NodeName != c.config.NodeName {
				return
			}
			if len(c.getNetworkPoliciesForPod(pod)) > 0 {
				c.queue.Add(syncKey)
			}
		},
	})

	// only process network policies that impact Pods on this node
	_, _ = networkpolicyInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			networkPolicy := obj.(*networkingv1.NetworkPolicy)
			if len(c.getLocalPodsForNetworkPolicy(networkPolicy)) > 0 {
				c.queue.Add(syncKey)
			}
		},
		UpdateFunc: func(old, cur interface{}) {
			networkPolicy := cur.(*networkingv1.NetworkPolicy)
			if len(c.getLocalPodsForNetworkPolicy(networkPolicy)) > 0 {
				c.queue.Add(syncKey)
			}
		},
		DeleteFunc: func(obj interface{}) {
			networkPolicy, ok := obj.(*networkingv1.NetworkPolicy)
			if !ok {
				// If we reached here it means the policy was deleted but its final state is unrecorded.
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					utilruntime.HandleError(fmt.Errorf("couldn't get object from tombstone %#v", obj))
					return
				}
				networkPolicy, ok = tombstone.Obj.(*networkingv1.NetworkPolicy)
				if !ok {
					utilruntime.HandleError(fmt.Errorf("tombstone contained object that is not a NetworkPolicy: %#v", obj))
					return
				}
			}
			if len(c.getLocalPodsForNetworkPolicy(networkPolicy)) > 0 {
				c.queue.Add(syncKey)
			}
		},
	})

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
		c.domainCache = NewDomainCache(config.QueueID + 1)
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

	return c, nil
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

	queue workqueue.TypedRateLimitingInterface[string]

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

	nfq     *nfqueue.Nfqueue
	flushed bool

	// Passively obtain the Domain A and AAAA records from the network
	domainCache *DomainCache
	nriPlugin   *nriPlugin
}

// Run will not return until stopCh is closed. workers determines how many
// endpoints will be handled in parallel.
func (c *Controller) Run(ctx context.Context) error {
	defer utilruntime.HandleCrash()
	defer c.queue.ShutDown()
	logger := klog.FromContext(ctx)

	logger.Info("Starting controller", "name", controllerName)
	defer logger.Info("Shutting down controller", "name", controllerName)

	// Wait for the caches to be synced
	logger.Info("Waiting for informer caches to sync")
	caches := []cache.InformerSynced{c.networkpoliciesSynced, c.namespacesSynced, c.podsSynced}
	if c.config.AdminNetworkPolicy || c.config.BaselineAdminNetworkPolicy {
		caches = append(caches, c.nodesSynced)
	}
	if !c.config.NRIdisabled {
		go func() {
			err := c.nriPlugin.stub.Run(ctx)
			if err != nil {
				klog.Infof("nri plugin exited: %v", err)
			}
		}()
	}
	if c.config.AdminNetworkPolicy {
		caches = append(caches, c.adminNetworkPolicySynced)
		go func() {
			err := c.domainCache.Run(ctx)
			if err != nil {
				klog.Infof("domain cache controller exited: %v", err)
			}
		}()
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

	// Start the workers after the repair loop to avoid races
	_ = c.syncNFTablesRules(ctx)
	defer c.cleanNFTablesRules(ctx)
	go wait.Until(c.runWorker, time.Second, ctx.Done())

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

		if c.evaluatePacket(ctx, packet) {
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

// evaluatePacket evalute the network policies using the following order:
// 1. AdminNetworkPolicies in Egress for the source Pod/IP
// 2. NetworkPolicies in Egress (if needed) for the source Pod/IP
// 3. BaselineAdminNetworkPolicies in Egress (if needed) for the source Pod/IP
// 4. AdminNetworkPolicies in Ingress for the destination Pod/IP
// 5. NetworkPolicies in Ingress (if needed) for the destination Pod/IP
// 6. BaselineAdminNetworkPolicies in Ingress (if needed) for the destination Pod/IP
func (c *Controller) evaluatePacket(ctx context.Context, p network.Packet) bool {
	logger := klog.FromContext(ctx)
	srcIP := p.SrcIP
	srcPod := c.getPodAssignedToIP(srcIP.String())
	srcPort := p.SrcPort
	dstIP := p.DstIP
	dstPod := c.getPodAssignedToIP(dstIP.String())
	dstPort := p.DstPort
	protocol := p.Proto

	// evaluatePacket() should be fast unless trace logging is enabled.
	// Logging optimization: We check if V(2) is enabled before hand,
	// rather than evaluating the all parameters make an unnecessary logger call
	tlogger := logger.V(2)
	if tlogger.Enabled() {
		srcPodStr, dstPodStr := "none", "none"
		if srcPod != nil {
			srcPodStr = srcPod.GetNamespace() + "/" + srcPod.GetName()
		}
		if dstPod != nil {
			dstPodStr = dstPod.GetNamespace() + "/" + dstPod.GetName()
		}
		tlogger.Info("Evaluating packet", "srcPod", srcPodStr, "dstPod", dstPodStr, "packet", p)
		tlogger = tlogger.WithValues("id", p.ID)
	}

	// Evalute Egress Policies

	// Admin Network Policies are evaluated first
	evaluateEgressNetworkPolicy := true
	if c.config.AdminNetworkPolicy {
		srcPodAdminNetworkPolices := c.getAdminNetworkPoliciesForPod(ctx, srcPod)
		action := c.evaluateAdminEgress(srcPodAdminNetworkPolices, dstPod, dstIP, dstPort, protocol)
		if tlogger.Enabled() {
			tlogger.Info("Egress AdminNetworkPolicies", "npolicies", len(srcPodAdminNetworkPolices), "action", action)
		}
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
		allowed := c.evaluator(ctx, srcPodNetworkPolices, networkingv1.PolicyTypeEgress, srcPod, srcPort, dstPod, dstIP, dstPort, protocol)
		if tlogger.Enabled() {
			tlogger.Info("Egress NetworkPolicies", "npolicies", len(srcPodNetworkPolices), "allowed", allowed)
		}
		if !allowed {
			return false
		}
	}
	if c.config.BaselineAdminNetworkPolicy && evaluateAdminEgressNetworkPolicy {
		srcPodBaselineAdminNetworkPolices := c.getBaselineAdminNetworkPoliciesForPod(ctx, srcPod)
		action := c.evaluateBaselineAdminEgress(srcPodBaselineAdminNetworkPolices, dstPod, dstIP, dstPort, protocol)
		if tlogger.Enabled() {
			tlogger.Info("Egress BaselineAdminNetworkPolicies", "npolicies", len(srcPodBaselineAdminNetworkPolices), "action", action)
		}
		switch action {
		case npav1alpha1.BaselineAdminNetworkPolicyRuleActionDeny: // Deny the packet no need to check anything else
			return false
		case npav1alpha1.BaselineAdminNetworkPolicyRuleActionAllow:
		}
	}

	// Evalute Ingress Policies

	// Admin Network Policies are evaluated first
	if c.config.AdminNetworkPolicy {
		dstPodAdminNetworkPolices := c.getAdminNetworkPoliciesForPod(ctx, dstPod)
		action := c.evaluateAdminIngress(dstPodAdminNetworkPolices, srcPod, dstPort, protocol)
		if tlogger.Enabled() {
			tlogger.Info("Ingress AdminNetworkPolicies", "npolicies", len(dstPodAdminNetworkPolices), "action", action)
		}
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
		allowed := c.evaluator(ctx, dstPodNetworkPolices, networkingv1.PolicyTypeIngress, dstPod, dstPort, srcPod, srcIP, srcPort, protocol)
		if tlogger.Enabled() {
			tlogger.Info("Ingress NetworkPolicies", "npolicies", len(dstPodNetworkPolices), "allowed", allowed)
		}
		return allowed
	}
	if c.config.BaselineAdminNetworkPolicy {
		dstPodBaselineAdminNetworkPolices := c.getBaselineAdminNetworkPoliciesForPod(ctx, dstPod)
		action := c.evaluateBaselineAdminIngress(dstPodBaselineAdminNetworkPolices, srcPod, dstPort, protocol)
		if tlogger.Enabled() {
			tlogger.Info("Ingress BaselineAdminNetworkPolicies", "npolicies", len(dstPodBaselineAdminNetworkPolices), "action", action)
		}
		switch action {
		case npav1alpha1.BaselineAdminNetworkPolicyRuleActionDeny: // Deny the packet no need to check anything else
			return false
		case npav1alpha1.BaselineAdminNetworkPolicyRuleActionAllow:
			return true
		}
	}
	return true
}

func (c *Controller) runWorker() {
	for c.processNextItem() {
	}
}

func (c *Controller) processNextItem() bool {
	// Wait until there is a new item in the working queue
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	// Tell the queue that we are done with processing this key. This unblocks the key for other workers
	// This allows safe parallel processing because two pods with the same key are never processed in
	// parallel.
	defer c.queue.Done(key)

	// Invoke the method containing the business logic
	err := c.syncNFTablesRules(context.Background())
	// Handle the error if something went wrong during the execution of the business logic
	c.handleErr(err, key)
	return true
}

// handleErr checks if an error happened and makes sure we will retry later.
func (c *Controller) handleErr(err error, key string) {
	if err == nil {
		// Forget about the #AddRateLimited history of the key on every successful synchronization.
		// This ensures that future processing of updates for this key is not delayed because of
		// an outdated error history.
		c.queue.Forget(key)
		return
	}

	// This controller retries 5 times if something goes wrong. After that, it stops trying.
	if c.queue.NumRequeues(key) < 5 {
		klog.ErrorS(err, "syncing", "key", key)

		// Re-enqueue the key rate limited. Based on the rate limiter on the
		// queue and the re-enqueue history, the key will be processed later again.
		c.queue.AddRateLimited(key)
		return
	}

	c.queue.Forget(key)
	// Report to an external entity that, even after several retries, we could not successfully process this key
	utilruntime.HandleError(err)
	klog.InfoS("Dropping out of the queue", "error", err, "key", key)
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

	// only if no admin network policies are used
	if !c.config.AdminNetworkPolicy && !c.config.BaselineAdminNetworkPolicy {
		// add set with Local Pod IPs impacted by network policies
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

		networkPolicies, err := c.networkpolicyLister.List(labels.Everything())
		if err != nil {
			return err
		}
		podV4IPs := sets.New[string]()
		podV6IPs := sets.New[string]()
		for _, networkPolicy := range networkPolicies {
			pods := c.getLocalPodsForNetworkPolicy(networkPolicy)
			for _, pod := range pods {
				for _, ip := range pod.Status.PodIPs {
					if netutils.IsIPv4String(ip.IP) {
						podV4IPs.Insert(ip.IP)
					} else {
						podV6IPs.Insert(ip.IP)
					}
				}
			}
		}

		var elementsV4, elementsV6 []nftables.SetElement
		for _, ip := range podV4IPs.UnsortedList() {
			addr, err := netip.ParseAddr(ip)
			if err != nil {
				continue
			}
			elementsV4 = append(elementsV4, nftables.SetElement{
				Key: addr.AsSlice(),
			})
		}
		for _, ip := range podV6IPs.UnsortedList() {
			addr, err := netip.ParseAddr(ip)
			if err != nil {
				continue
			}
			elementsV6 = append(elementsV6, nftables.SetElement{
				Key: addr.AsSlice(),
			})
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
	if !c.config.AdminNetworkPolicy && !c.config.BaselineAdminNetworkPolicy {
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
		c.addDNSRacersWorkaroundRules(nft, table)
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
func (c *Controller) addDNSRacersWorkaroundRules(nft *nftables.Conn, table *nftables.Table) {
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
	if !c.config.AdminNetworkPolicy && !c.config.BaselineAdminNetworkPolicy {
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
