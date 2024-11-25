package networkpolicy

import (
	"context"
	"fmt"
	"os"
	"time"

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
	interceptor interceptor,
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
		interceptor: interceptor,
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

	interceptor interceptor
}

//go:generate stringer -type=Verdict
type Verdict int

// Verdicts
const (
	Drop Verdict = iota
	Accept
)

type interceptor interface {
	Sync(ctx context.Context, podV4IPs, podV6IPs sets.Set[string]) error
}

// Run will return after caches are synced but otherwise does not block
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

	// Start the workers after the repair loop to avoid races
	go wait.Until(c.runWorker, time.Second, ctx.Done())

	return nil
}

// Parse the packet and check if it should be accepted
// Packets should be evaludated independently in each direction
func (c *Controller) EvaluatePacket(ctx context.Context, packet Packet) Verdict {

	startTime := time.Now()
	logger := klog.FromContext(ctx)

	logger.V(2).Info("Processing sync for packet", "id", packet.Id)
	verdict := Accept
	defer func() {
		processingTime := float64(time.Since(startTime).Microseconds())
		packetProcessingHist.WithLabelValues(string(packet.proto), string(packet.family)).Observe(processingTime)
		packetProcessingSum.Observe(processingTime)
		verdictStr := verdict.String()
		packetCounterVec.WithLabelValues(string(packet.proto), string(packet.family), verdictStr).Inc()
		logger.V(2).Info("Finished syncing packet", "id", packet.Id, "duration", time.Since(startTime), "verdict", verdictStr)
	}()

	if c.evaluatePacket(ctx, packet) {
		verdict = Accept
	} else {
		verdict = Drop
	}
	return verdict
}

// evaluatePacket evalute the network policies using the following order:
// 1. AdminNetworkPolicies in Egress for the source Pod/IP
// 2. NetworkPolicies in Egress (if needed) for the source Pod/IP
// 3. BaselineAdminNetworkPolicies in Egress (if needed) for the source Pod/IP
// 4. AdminNetworkPolicies in Ingress for the destination Pod/IP
// 5. NetworkPolicies in Ingress (if needed) for the destination Pod/IP
// 6. BaselineAdminNetworkPolicies in Ingress (if needed) for the destination Pod/IP
func (c *Controller) evaluatePacket(ctx context.Context, p Packet) bool {
	logger := klog.FromContext(ctx)
	srcIP := p.srcIP
	srcPod := c.getPodAssignedToIP(srcIP.String())
	srcPort := p.srcPort
	dstIP := p.dstIP
	dstPod := c.getPodAssignedToIP(dstIP.String())
	dstPort := p.dstPort
	protocol := p.proto

	// evaluatePacket() should be fast unless trace logging is enabled.
	// Logging optimization: We check if V(2) is enabled before hand,
	// rather than evaluating the all parameters make an unnecessary logger call
	tlogger := logger.V(2)
	if tlogger.Enabled() {
		tlogger.Info("Evaluating packet", "packet", p)
		tlogger = tlogger.WithValues("id", p.Id)
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

	networkPolicies, err := c.networkpolicyLister.List(labels.Everything())
	if err != nil {
		c.handleErr(err, key)
		return true
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

	err = c.interceptor.Sync(context.Background(), podV4IPs, podV6IPs)
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
