package networkpolicy

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-iptables/iptables"
	nfqueue "github.com/florianl/go-nfqueue"
	"github.com/mdlayher/netlink"

	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
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
	controllerName = "kube-netpol"
	podIPIndex     = "podIPKeyIndex"
)

type Config struct {
	FailOpen bool // allow traffic if the controller is not available
	QueueID  int
}

// detect if the system uses iptables legacy
func iptablesLegacy() bool {
	// only support IPv4 with iptables for simplicity
	path, err := exec.LookPath("iptables")
	if err != nil {
		return false
	}
	cmd := exec.Command(path, "--version")
	var out bytes.Buffer
	cmd.Stdout = &out
	err = cmd.Run()
	if err != nil {
		return false
	}
	if strings.Contains(out.String(), "legacy") {
		return true
	}
	return false
}

// NewController returns a new *Controller.
func NewController(client clientset.Interface,
	networkpolicyInformer networkinginformers.NetworkPolicyInformer,
	namespaceInformer coreinformers.NamespaceInformer,
	podInformer coreinformers.PodInformer,
	config Config,
) *Controller {
	klog.V(2).Info("Creating event broadcaster")
	broadcaster := record.NewBroadcaster()
	broadcaster.StartStructuredLogging(0)
	broadcaster.StartRecordingToSink(&v1core.EventSinkImpl{Interface: client.CoreV1().Events("")})
	recorder := broadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: controllerName})

	c := &Controller{
		client: client,
		config: config,
	}

	if iptablesLegacy() {
		ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
		if err != nil {
			klog.Fatalf("Error creating iptables: %v", err)
		}
		klog.Infof("Using iptables legacy")
		c.ipt = ipt
	} else {
		nft, err := knftables.New(knftables.InetFamily, "kube-netpol")
		if err != nil {
			klog.Infof("Error initializing nftables: %v", err)
			ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
			if err != nil {
				klog.Fatalf("Error creating iptables: %v", err)
			}
			klog.Infof("Using iptables")
			c.ipt = ipt
		} else {
			klog.Infof("Using nftables")
			c.nft = nft
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

	// function to get the Pod given an IP
	// if an error or not found it returns nil
	getPodAssignedToIP func(podIP string) *v1.Pod

	nft     knftables.Interface // install the necessary nftables rules
	ipt     *iptables.IPTables  // on old systems we need to support iptables
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
	if !cache.WaitForNamedCacheSync(controllerName, ctx.Done(), c.networkpoliciesSynced, c.namespacesSynced, c.podsSynced) {
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

	if c.ipt != nil {
		// Start the workers after the repair loop to avoid races
		klog.Info("Syncing iptables rules")
		c.syncIptablesRules()
		defer c.cleanIptablesRules()
		go wait.Until(c.syncIptablesRules, 60*time.Second, ctx.Done())
	} else {
		klog.Info("Syncing nftables rules")
		c.syncNFTablesRules(ctx)
		defer c.cleanNFTablesRules()
		// FIXME: there should be no need to ever resync our rules, but if we're going to
		// do that, then knftables should provide us with an API to tell us when we need
		// to resync (using `nft monitor` or direct netlink), rather than us polling.
		go wait.Until(func() { c.syncNFTablesRules(ctx) }, 60*time.Second, ctx.Done())
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
		klog.Infof("could not open nfqueue socket: %v", err)
		return err
	}
	defer nf.Close()

	c.nfq = nf

	// Parse the packet and check if should be accepted
	fn := func(a nfqueue.Attribute) int {
		startTime := time.Now()
		klog.V(2).Infof("Processing sync for packet %d", *a.PacketID)

		packet, err := parsePacket(*a.Payload)
		if err != nil {
			klog.Infof("Can not process packet %d accepting it: %v", *a.PacketID, err)
			c.nfq.SetVerdict(*a.PacketID, nfqueue.NfAccept) //nolint:errcheck
		}

		verdict := c.acceptPacket(packet)
		if verdict {
			c.nfq.SetVerdict(*a.PacketID, nfqueue.NfAccept) //nolint:errcheck
		} else {
			c.nfq.SetVerdict(*a.PacketID, nfqueue.NfDrop) //nolint:errcheck
		}

		processingTime := float64(time.Since(startTime).Microseconds())
		packetProcessingHist.WithLabelValues(string(packet.proto), string(packet.family)).Observe(processingTime)
		packetProcessingSum.Observe(processingTime)
		packetCounterVec.WithLabelValues(string(packet.proto), string(packet.family)).Inc()
		klog.V(2).Infof("Finished syncing packet %d took: %v accepted: %v", *a.PacketID, time.Since(startTime), verdict)
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

func (c *Controller) syncIptablesRules() {
	queueRule := []string{"-m", "conntrack", "--ctstate", "NEW", "-j", "NFQUEUE", "--queue-num", strconv.Itoa(c.config.QueueID)}
	if c.config.FailOpen {
		queueRule = append(queueRule, "--queue-bypass")
	}

	// kube-proxy install the reject rules for Services with Endpoints on the FORWARD hook
	// nfqueue either accepts or drops https://netfilter-devel.vger.kernel.narkive.com/dGk9ZPzK/nfqueue-target-with-treat-accept-as-continue
	// We can append the rule after the kube-proxy ones, but that will always depend on the order of the components
	// to be installed so it will be racy.
	// Since nftables does not seem to have that problem and we only offer iptables-legacy for backwards compatibility
	// use the mangle table that happens before for filtering.
	if err := c.ipt.InsertUnique("mangle", "FORWARD", 1, queueRule...); err != nil {
		klog.Infof("error syncing iptables rule %v", err)
	}
}

func (c *Controller) cleanIptablesRules() {
	queueRule := []string{"-m", "conntrack", "--ctstate", "NEW", "-j", "NFQUEUE", "--queue-num", strconv.Itoa(c.config.QueueID)}
	if c.config.FailOpen {
		queueRule = append(queueRule, "--queue-bypass")
	}

	if err := c.ipt.Delete("mangle", "FORWARD", queueRule...); err != nil {
		klog.Infof("error deleting iptables rule %v", err)
	}
}

func (c *Controller) getNetworkPoliciesForPod(pod *v1.Pod) []*networkingv1.NetworkPolicy {
	if pod == nil {
		return nil
	}
	// Get all the network policies that affect this pod
	networkPolices, err := c.networkpolicyLister.NetworkPolicies(pod.Namespace).List(labels.Everything())
	if err != nil {
		return nil
	}
	return networkPolices
}

func (c *Controller) acceptPacket(p packet) bool {
	srcIP := p.srcIP
	srcPod := c.getPodAssignedToIP(srcIP.String())
	srcPort := p.srcPort
	dstIP := p.dstIP
	dstPod := c.getPodAssignedToIP(dstIP.String())
	dstPort := p.dstPort
	protocol := p.proto
	srcPodNetworkPolices := c.getNetworkPoliciesForPod(srcPod)
	dstPodNetworkPolices := c.getNetworkPoliciesForPod(dstPod)

	msg := fmt.Sprintf("checking packet %s:", p.String())
	if srcPod != nil {
		msg += fmt.Sprintf(" SrcPod (%s/%s): %d NetworkPolicy", srcPod.Name, srcPod.Namespace, len(srcPodNetworkPolices))
	}
	if dstPod != nil {
		msg += fmt.Sprintf(" DstPod (%s/%s): %d NetworkPolicy", dstPod.Name, dstPod.Namespace, len(dstPodNetworkPolices))
	}
	klog.V(2).Infof("%s", msg)

	// For a connection from a source pod to a destination pod to be allowed,
	// both the egress policy on the source pod and the ingress policy on the
	// destination pod need to allow the connection.
	// If either side does not allow the connection, it will not happen.

	// This is the first packet originated from srcPod so we need to check:
	// 1. srcPod egress is accepted
	// 2. dstPod ingress is accepted
	return c.evaluator(srcPodNetworkPolices, networkingv1.PolicyTypeEgress, srcPod, srcIP, srcPort, dstPod, dstIP, dstPort, protocol) &&
		c.evaluator(dstPodNetworkPolices, networkingv1.PolicyTypeIngress, dstPod, dstIP, dstPort, srcPod, srcIP, srcPort, protocol)
}

// validator obtains a verdict for network policies that applies to a src Pod in the direction
// passed as parameter
func (c *Controller) evaluator(
	networkPolicies []*networkingv1.NetworkPolicy, networkPolictType networkingv1.PolicyType,
	srcPod *v1.Pod, srcIP net.IP, srcPort int, dstPod *v1.Pod, dstIP net.IP, dstPort int, proto v1.Protocol) bool {

	// no network policies implies allow all by default
	if len(networkPolicies) == 0 {
		return true
	}

	// no network policies matching the Pod allows all
	verdict := true
	for _, netpol := range networkPolicies {
		// podSelector selects the pods to which this NetworkPolicy object applies.
		// The array of ingress rules is applied to any pods selected by this field.
		// Multiple network policies can select the same set of pods. In this case,
		// the ingress rules for each are combined additively.
		// This field is NOT optional and follows standard label selector semantics.
		// An empty podSelector matches all pods in this namespace.
		podSelector, err := metav1.LabelSelectorAsSelector(&netpol.Spec.PodSelector)
		if err != nil {
			klog.Infof("error parsing PodSelector: %v", err)
			continue
		}
		// networkPolicy does not selects the pod try the next network policy
		if !podSelector.Matches(labels.Set(srcPod.Labels)) {
			klog.V(2).Infof("Pod %s/%s does not match NetworkPolicy %s/%s", srcPod.Name, srcPod.Namespace, netpol.Name, netpol.Namespace)
			continue
		}

		for _, policyType := range netpol.Spec.PolicyTypes {
			// only evaluate one direction
			if policyType != networkPolictType {
				continue
			}

			if policyType == networkingv1.PolicyTypeEgress {
				// egress is a list of egress rules to be applied to the selected pods. Outgoing traffic
				// is allowed if there are no NetworkPolicies selecting the pod (and cluster policy
				// otherwise allows the traffic), OR if the traffic matches at least one egress rule
				// across all of the NetworkPolicy objects whose podSelector matches the pod. If
				// this field is empty then this NetworkPolicy limits all outgoing traffic (and serves
				// solely to ensure that the pods it selects are isolated by default).

				// if there is at least one network policy matching the Pod it defaults to deny
				verdict = false
				if netpol.Spec.Egress == nil {
					klog.V(2).Infof("Pod %s/%s has limited all egress traffic by NetworkPolicy %s/%s", srcPod.Name, srcPod.Namespace, netpol.Name, netpol.Namespace)
					continue
				}
				// This evaluator only evaluates one policyType, if it matches then traffic is allowed
				if c.evaluateEgress(netpol.Namespace, netpol.Spec.Egress, srcPod, dstPod, dstIP, dstPort, proto) {
					return true
				}
			}

			if policyType == networkingv1.PolicyTypeIngress {
				// ingress is a list of ingress rules to be applied to the selected pods.
				// Traffic is allowed to a pod if there are no NetworkPolicies selecting the pod
				// (and cluster policy otherwise allows the traffic), OR if the traffic source is
				// the pod's local node, OR if the traffic matches at least one ingress rule
				// across all of the NetworkPolicy objects whose podSelector matches the pod. If
				// this field is empty then this NetworkPolicy does not allow any traffic (and serves
				// solely to ensure that the pods it selects are isolated by default)

				// if there is at least one network policy matching the Pod it defaults to deny
				verdict = false
				if netpol.Spec.Ingress == nil {
					klog.V(2).Infof("Pod %s/%s has limited all ingress traffic by NetworkPolicy %s/%s", dstPod.Name, dstPod.Namespace, netpol.Name, netpol.Namespace)
					continue
				}
				// This evaluator only evaluates one policyType, if it matches then traffic is allowed
				if c.evaluateIngress(netpol.Namespace, netpol.Spec.Ingress, srcPod, srcPort, dstPod, dstIP, proto) {
					return true
				}
			}
		}
	}

	return verdict
}

func (c *Controller) evaluateIngress(netpolNamespace string, ingressRules []networkingv1.NetworkPolicyIngressRule, srcPod *v1.Pod, srcPort int, dstPod *v1.Pod, dstIP net.IP, proto v1.Protocol) bool {
	// assume srcPod and ingressRules are not nil
	if len(ingressRules) == 0 {
		klog.V(2).Infof("Pod %s/%s has allowed all egress traffic", srcPod.Name, srcPod.Namespace)
		return true
	}

	for _, rule := range ingressRules {
		// Evaluate if Port is accessible in the specified Pod
		if !c.evaluatePorts(rule.Ports, srcPod, srcPort, proto) {
			klog.V(2).Infof("Pod %s/%s is not allowed to be connected on port %d", srcPod.Name, srcPod.Namespace, srcPort)
			continue
		}

		// from is a list of sources which should be able to access the pods selected for this rule.
		// Items in this list are combined using a logical OR operation. If this field is
		// empty or missing, this rule matches all sources (traffic not restricted by
		// source). If this field is present and contains at least one item, this rule
		// allows traffic only if the traffic matches at least one item in the from list.
		if len(rule.From) == 0 {
			klog.V(2).Infof("Pod %s/%s is allowed to connect from any destination", srcPod.Name, srcPod.Namespace)
			return true
		}
		for _, peer := range rule.From {
			// IPBlock describes a particular CIDR (Ex. "192.168.1.0/24","2001:db8::/64") that is allowed
			// to the pods matched by a NetworkPolicySpec's podSelector. The except entry describes CIDRs
			// that should not be included within this rule.
			if peer.IPBlock != nil {
				if c.evaluateIPBlocks(peer.IPBlock, dstIP) {
					klog.V(2).Infof("Pod %s/%s is not accessible from %s", srcPod.Name, srcPod.Namespace, dstIP)
					return true
				}
				continue
			}

			// traffic coming from external does not match selectors
			if dstPod == nil {
				continue
			}

			if peer.NamespaceSelector != nil || peer.PodSelector != nil {
				if c.evaluateSelectors(peer.PodSelector, peer.NamespaceSelector, dstPod, netpolNamespace) {
					klog.V(2).Infof("Pod %s/%s is accessible from Pod %s/%s because match selectors", srcPod.Name, srcPod.Namespace, dstPod.Name, dstPod.Namespace)
					return true
				}
			}
		}
	}
	return false
}

func (c *Controller) evaluateEgress(netpolNamespace string, egressRules []networkingv1.NetworkPolicyEgressRule, srcPod *v1.Pod, dstPod *v1.Pod, dstIP net.IP, dstPort int, proto v1.Protocol) bool {
	if len(egressRules) == 0 {
		klog.V(2).Infof("Pod %s/%s has allowed all egress traffic", srcPod.Name, srcPod.Namespace)
		return true
	}

	for _, rule := range egressRules {
		// Evaluate if Pod is allowed to connect to dstPort
		if !c.evaluatePorts(rule.Ports, dstPod, dstPort, proto) {
			klog.V(2).Infof("Pod %s/%s is not allowed to connect to port %d", srcPod.Name, srcPod.Namespace, dstPort)
			continue
		}
		// to is a list of destinations for outgoing traffic of pods selected for this rule.
		// Items in this list are combined using a logical OR operation. If this field is
		// empty or missing, this rule matches all destinations (traffic not restricted by
		// destination). If this field is present and contains at least one item, this rule
		// allows traffic only if the traffic matches at least one item in the to list.
		if len(rule.To) == 0 {
			klog.V(2).Infof("Pod %s/%s is allowed to connect to any destination", srcPod.Name, srcPod.Namespace)
			return true
		}
		for _, peer := range rule.To {
			// IPBlock describes a particular CIDR (Ex. "192.168.1.0/24","2001:db8::/64") that is allowed
			// to the pods matched by a NetworkPolicySpec's podSelector. The except entry describes CIDRs
			// that should not be included within this rule.
			if peer.IPBlock != nil {
				if c.evaluateIPBlocks(peer.IPBlock, dstIP) {
					klog.V(2).Infof("Pod %s/%s is allowed to connect to %s", srcPod.Name, srcPod.Namespace, dstIP)
					return true
				}
				continue
			}

			// NamespaceSelector and PodSelector only apply to destination Pods
			if dstPod == nil {
				continue
			}

			if peer.NamespaceSelector != nil || peer.PodSelector != nil {
				if c.evaluateSelectors(peer.PodSelector, peer.NamespaceSelector, dstPod, netpolNamespace) {
					klog.V(2).Infof("Pod %s/%s is allowed to connect because of Pod and Namespace selectors", srcPod.Name, srcPod.Namespace)
					return true
				}
			}
		}
	}
	return false
}

func (c *Controller) evaluateSelectors(peerPodSelector *metav1.LabelSelector, peerNSSelector *metav1.LabelSelector, pod *v1.Pod, policyNs string) bool {
	// avoid panics
	if pod == nil {
		return true
	}

	// podSelector is a label selector which selects pods. This field follows standard label
	// selector semantics; if present but empty, it selects all pods.
	// If namespaceSelector is also set, then the NetworkPolicyPeer as a whole selects
	// the pods matching podSelector in the Namespaces selected by NamespaceSelector.
	if peerPodSelector != nil {
		podSelector, err := metav1.LabelSelectorAsSelector(peerPodSelector)
		if err != nil {
			klog.Infof("Accepting packet, error: %v", err)
			return true
		}
		// networkPolicy does not selects the pod
		if !podSelector.Matches(labels.Set(pod.Labels)) {
			return false
		}
		// if peerNSSelector selects the pods matching podSelector in the policy's own namespace
		if peerNSSelector == nil {
			return pod.Namespace == policyNs
		}
	}
	// namespaceSelector selects namespaces using cluster-scoped labels. This field follows
	// standard label selector semantics; if present but empty, it selects all namespaces.

	// If podSelector is also set, then the NetworkPolicyPeer as a whole selects
	// the pods matching podSelector in the namespaces selected by namespaceSelector.
	// Otherwise it selects all pods in the namespaces selected by namespaceSelector.
	if peerNSSelector != nil {
		// if present but empty, it selects all namespaces.
		if len(peerNSSelector.MatchLabels)+len(peerNSSelector.MatchExpressions) == 0 {
			return true
		}

		nsSelector, err := metav1.LabelSelectorAsSelector(peerNSSelector)
		if err != nil {
			klog.Infof("Accepting packet, error: %v", err)
			return true
		}

		namespaces, err := c.namespaceLister.List(nsSelector)
		if err != nil {
			klog.Infof("Accepting packet, error: %v", err)
			return true
		}
		for _, ns := range namespaces {
			if pod.Namespace == ns.Name {
				return true
			}
		}
		return false
	}
	// at least podSelector or nsSelector is guaranteed to be not nil
	// it should have returned before reaching this point
	return true
}

func (c *Controller) evaluateIPBlocks(ipBlock *networkingv1.IPBlock, ip net.IP) bool {
	if ipBlock == nil {
		return true
	}

	_, cidr, err := net.ParseCIDR(ipBlock.CIDR)
	if err != nil { // this has been validated by the API
		return true
	}

	if !cidr.Contains(ip) {
		return false
	}

	for _, except := range ipBlock.Except {
		_, cidr, err := net.ParseCIDR(except)
		if err != nil { // this has been validated by the API
			return true
		}
		if cidr.Contains(ip) {
			return false
		}
	}
	// it matched the cidr and didn't match the exceptions
	return true
}

func (c *Controller) evaluatePorts(networkPolicyPorts []networkingv1.NetworkPolicyPort, pod *v1.Pod, port int, protocol v1.Protocol) bool {
	// ports is a list of ports,  each item in this list is combined using a logical OR.
	// If this field is empty or missing, this rule matches all ports (traffic not restricted by port).
	// If this field is present and contains at least one item, then this rule allows
	// traffic only if the traffic matches at least one port in the list.
	if len(networkPolicyPorts) == 0 {
		return true
	}

	for _, policyPort := range networkPolicyPorts {
		if protocol != *policyPort.Protocol {
			continue
		}
		// matches all ports
		if policyPort.Port == nil {
			return true
		}
		if port == policyPort.Port.IntValue() {
			return true
		}
		if pod != nil && policyPort.Port.StrVal != "" {
			for _, container := range pod.Spec.Containers {
				for _, p := range container.Ports {
					if p.Name == policyPort.Port.StrVal &&
						p.ContainerPort == int32(port) &&
						p.Protocol == protocol {
						return true
					}
				}
			}
		}
		// endPort indicates that the range of ports from port to endPort if set, inclusive,
		// should be allowed by the policy. This field cannot be defined if the port field
		// is not defined or if the port field is defined as a named (string) port.
		// The endPort must be equal or greater than port.
		if policyPort.EndPort == nil {
			continue
		}
		if port > policyPort.Port.IntValue() && int32(port) <= *policyPort.EndPort {
			return true
		}
	}
	return false
}
