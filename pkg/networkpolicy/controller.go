package networkpolicy

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-iptables/iptables"
	nfqueue "github.com/florianl/go-nfqueue"
	"github.com/mdlayher/netlink"

	v1 "k8s.io/api/core/v1"
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
		verdict := nfqueue.NfDrop
		if c.config.FailOpen {
			verdict = nfqueue.NfAccept
		}

		startTime := time.Now()
		klog.V(2).Infof("Processing sync for packet %d", *a.PacketID)

		packet, err := parsePacket(*a.Payload)
		if err != nil {
			klog.Infof("Can not process packet %d accepting it: %v", *a.PacketID, err)
			c.nfq.SetVerdict(*a.PacketID, verdict) //nolint:errcheck
			return 0
		}

		defer func() {
			processingTime := float64(time.Since(startTime).Microseconds())
			packetProcessingHist.WithLabelValues(string(packet.proto), string(packet.family)).Observe(processingTime)
			packetProcessingSum.Observe(processingTime)
			packetCounterVec.WithLabelValues(string(packet.proto), string(packet.family)).Inc()
			klog.V(2).Infof("Finished syncing packet %d took: %v accepted: %v", *a.PacketID, time.Since(startTime), verdict == nfqueue.NfAccept)
		}()

		// Network Policy
		if c.acceptNetworkPolicy(packet) {
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
