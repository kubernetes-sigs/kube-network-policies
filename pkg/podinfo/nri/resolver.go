//go:build linux

package nri

import (
	"context"
	"fmt"
	"sync"
	"time"

	nriapi "github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"k8s.io/apimachinery/pkg/util/sets"
	coreinformers "k8s.io/client-go/informers/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog/v2"
	"sigs.k8s.io/kube-network-policies/pkg/api"
	"sigs.k8s.io/kube-network-policies/pkg/podinfo"
)

var _ podinfo.IPResolver = &NRIResolver{}
var _ api.PodInfoProvider = &NRIResolver{}
var _ stub.StopPodInterface = &NRIResolver{}

// sandboxRecord is what the resolver knows about a sandbox reported by the runtime.
type sandboxRecord struct {
	podInfo *api.PodInfo
	// ips are the IPs claimed by the sandbox, some of them may be owned by
	// another sandbox now.
	ips []string
}

// NRIResolver is a standalone component that listens to NRI events
// and maintains a cache of PodInfo objects.
type NRIResolver struct {
	nodeName string
	stub     stub.Stub
	nsLister corelisters.NamespaceLister

	// mu protects sandboxes, ipOwners and stopped.
	mu sync.Mutex
	// sandboxes indexes the sandboxes by ID, so their IPs can be released on
	// removal even if the removal event does not include them.
	sandboxes map[string]*sandboxRecord
	// ipOwners maps an IP to the ID of the sandbox that owns it. An IP claimed
	// by more than one sandbox in a runtime snapshot has no owner until a
	// sandbox claims it again in RunPodSandbox or a later snapshot.
	ipOwners map[string]string
	// stopped has the IDs of the stopped sandboxes. A stopped sandbox never
	// runs again, but the runtime snapshot lists it until it is removed.
	stopped sets.Set[string]
}

// NewNRIResolver creates a new resolver that looks up pods via the NRI plugin.
func NewNRIResolver(ctx context.Context, nodeName string, namespaceInformer coreinformers.NamespaceInformer) (*NRIResolver, error) {
	const (
		pluginName = "kube-network-policies-podip-resolver"
		pluginIdx  = "10"
	)
	p := &NRIResolver{
		nodeName:  nodeName,
		sandboxes: make(map[string]*sandboxRecord),
		ipOwners:  make(map[string]string),
		stopped:   sets.New[string](),
	}
	if namespaceInformer != nil {
		p.nsLister = namespaceInformer.Lister()
	}

	opts := []stub.Option{
		stub.WithOnClose(p.onClose),
		stub.WithPluginName(pluginName),
		stub.WithPluginIdx(pluginIdx),
	}
	stub, err := stub.New(p, opts...)
	if err != nil {
		return nil, err
	}
	p.stub = stub

	// retry for a while, but reset the counter if the plugin proves to be stable
	go func() {
		const initialMaxRetries = 10
		maxRetries := initialMaxRetries
		const stabilityThreshold = 5 * time.Minute // if the plugin runs for this long, we consider it stable
		var err error

		for maxRetries > 0 {
			select {
			case <-ctx.Done():
				return
			default:
			}
			startTime := time.Now()
			err = p.Run(ctx)

			// if the plugin was stable for a while, reset the backoff counter
			if time.Since(startTime) > stabilityThreshold {
				klog.Infof("nri plugin was stable for more than %v, resetting retry counter", stabilityThreshold)
				maxRetries = initialMaxRetries
			}

			if err != nil {
				klog.Infof("nri plugin exited, retrying %d times in 5 seconds: %v", maxRetries-1, err)
			}
			maxRetries--
			time.Sleep(5 * time.Second)
		}
		klog.Infof("nri plugin exited, restart to reconnnect: %v", err)

	}()

	return p, nil
}

// LookupPod implements the Resolver interface using the NRI plugin.
func (p *NRIResolver) LookupPod(ip string) (string, bool) {
	podInfo, found := p.GetPodInfoByIP(ip)
	if !found {
		return "", false
	}
	return podInfo.Namespace.Name + "/" + podInfo.Name, true
}

func (p *NRIResolver) Run(ctx context.Context) error {
	return p.stub.Run(ctx)
}

// GetPodInfoByIP returns a PodInfo object from the local cache.
func (p *NRIResolver) GetPodInfoByIP(ip string) (*api.PodInfo, bool) {
	// A nil resolver has no cache, it is returned when the NRI plugin can not be created.
	if p == nil {
		return nil, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	id, found := p.ipOwners[ip]
	if !found {
		return nil, false
	}
	sandbox, found := p.sandboxes[id]
	if !found {
		return nil, false
	}
	return sandbox.podInfo, true
}

// Synchronize replaces the cache with the runtime snapshot.
func (p *NRIResolver) Synchronize(_ context.Context, pods []*nriapi.PodSandbox, containers []*nriapi.Container) ([]*nriapi.ContainerUpdate, error) {
	klog.Infof("Synchronized state with the runtime (%d pods, %d containers)...",
		len(pods), len(containers))

	listed := sets.New[string]()
	var running []*sandboxRecord
	var runningIDs []string
	for _, pod := range pods {
		listed.Insert(pod.GetId())
		ips := getPodIPs(pod)
		podKey := fmt.Sprintf("%s/%s", pod.GetNamespace(), pod.GetName())
		nsPath := getNetworkNamespace(pod)
		klog.V(4).Infof("pod=%s netns=%s ips=%v", podKey, nsPath, ips)
		// The snapshot includes stopped sandboxes and containerd 2.1+ still
		// reports the IPs they had, so a sandbox only owns its IPs if its
		// network namespace still exists.
		if len(ips) > 0 {
			if err := checkNetworkNamespace(nsPath); err != nil {
				klog.V(2).Infof("Ignoring Pod %s sandbox=%s ips=%v, its network namespace %q can not be opened: %v", podKey, pod.GetId(), ips, nsPath, err)
				continue
			}
		}
		running = append(running, &sandboxRecord{podInfo: p.getPodInfo(pod), ips: ips})
		runningIDs = append(runningIDs, pod.GetId())
	}

	// The stopped sandboxes are checked with the lock held, so a concurrent
	// StopPodSandbox is not lost.
	p.mu.Lock()
	defer p.mu.Unlock()
	sandboxes := make(map[string]*sandboxRecord, len(running))
	ipOwners := make(map[string]string)
	// An IP claimed by more than one sandbox may have been reused and the
	// snapshot does not tell which sandbox owns it.
	conflicts := sets.New[string]()
	for i, sandbox := range running {
		id := runningIDs[i]
		// The network namespace may still exist if tearing it down failed.
		if p.stopped.Has(id) {
			klog.V(4).Infof("Ignoring stopped sandbox=%s ips=%v", id, sandbox.ips)
			continue
		}
		sandboxes[id] = sandbox
		for _, ip := range sandbox.ips {
			if owner, ok := ipOwners[ip]; ok && owner != id {
				conflicts.Insert(ip)
			}
			ipOwners[ip] = id
		}
	}
	for ip := range conflicts {
		klog.Infof("IP %s is claimed by more than one sandbox, ignoring it until a sandbox claims it", ip)
		delete(ipOwners, ip)
	}
	p.sandboxes = sandboxes
	p.ipOwners = ipOwners
	// The sandboxes that are not listed have been removed.
	p.stopped = p.stopped.Intersection(listed)
	return nil, nil
}

func (p *NRIResolver) Shutdown(_ context.Context) {
	klog.Info("Runtime shutting down...")
}

func (p *NRIResolver) RunPodSandbox(_ context.Context, pod *nriapi.PodSandbox) error {
	ips := getPodIPs(pod)
	podKey := fmt.Sprintf("%s/%s", pod.GetNamespace(), pod.GetName())
	klog.V(4).Infof("Starting Pod %s netns=%s ips=%v", podKey, getNetworkNamespace(pod), ips)
	podInfo := p.getPodInfo(pod)

	p.mu.Lock()
	defer p.mu.Unlock()
	// The sandbox may be registered again with different IPs.
	p.releaseSandbox(pod.GetId())
	p.stopped.Delete(pod.GetId())
	p.sandboxes[pod.GetId()] = &sandboxRecord{podInfo: podInfo, ips: ips}
	// The runtime has just assigned these IPs to the sandbox, so it owns them
	// even if another sandbox claimed them before.
	for _, ip := range ips {
		p.ipOwners[ip] = pod.GetId()
	}
	return nil
}

// StopPodSandbox is called when the runtime stops the sandbox, before it tears
// down the network and releases the IPs. The event may not include the IPs and
// the IPs may have been reused by another sandbox, so release the IPs cached
// for the sandbox that it still owns.
func (p *NRIResolver) StopPodSandbox(_ context.Context, pod *nriapi.PodSandbox) error {
	podKey := fmt.Sprintf("%s/%s", pod.GetNamespace(), pod.GetName())
	klog.V(4).Infof("Stopping Pod %s sandbox=%s", podKey, pod.GetId())
	p.mu.Lock()
	defer p.mu.Unlock()
	p.releaseSandbox(pod.GetId())
	p.stopped.Insert(pod.GetId())
	return nil
}

func (p *NRIResolver) RemovePodSandbox(_ context.Context, pod *nriapi.PodSandbox) error {
	// The event may not include the IPs because of this bug in
	// https://github.com/containerd/containerd/pull/11331 and the IPs may have
	// been reused by another sandbox, so release the IPs cached for the sandbox.
	podKey := fmt.Sprintf("%s/%s", pod.GetNamespace(), pod.GetName())
	klog.V(4).Infof("Removing Pod %s sandbox=%s", podKey, pod.GetId())
	p.mu.Lock()
	defer p.mu.Unlock()
	p.releaseSandbox(pod.GetId())
	// The sandbox does not exist anymore, so a later snapshot can not list it.
	p.stopped.Delete(pod.GetId())
	return nil
}

// releaseSandbox forgets a sandbox and the IPs it still owns. It must be
// called with p.mu held.
func (p *NRIResolver) releaseSandbox(id string) {
	sandbox, found := p.sandboxes[id]
	if !found {
		return
	}
	for _, ip := range sandbox.ips {
		if p.ipOwners[ip] == id {
			delete(p.ipOwners, ip)
		}
	}
	delete(p.sandboxes, id)
}

func (p *NRIResolver) onClose() {
	klog.Infof("Connection to the runtime lost, exiting...")
}

// getPodInfo returns an PodInfo object obtained with the local information
// so it solves the race problem caused by waiting for the kubelet to propagate
// the local information to the apiserver and the agent receiving it
func (p *NRIResolver) getPodInfo(pod *nriapi.PodSandbox) *api.PodInfo {
	podInfo := &api.PodInfo{
		Name: pod.GetName(),
		// TODO: remove the specifics from containerd
		Labels: pod.GetLabels(),
		Namespace: &api.Namespace{
			Name: pod.GetNamespace(),
		},
		Node: &api.Node{
			Name: p.nodeName,
		},
		LastUpdated: time.Now().Unix(),
	}
	if p.nsLister != nil {
		ns, err := p.nsLister.Get(pod.GetNamespace())
		if err == nil {
			podInfo.Namespace.Labels = ns.Labels
		}
	}
	return podInfo
}

func getNetworkNamespace(pod *nriapi.PodSandbox) string {
	// get the pod network namespace
	for _, namespace := range pod.Linux.GetNamespaces() {
		if namespace.Type == "network" {
			return namespace.Path
		}
	}
	return ""
}

// checkNetworkNamespace returns an error if the network namespace does not
// exist or can not be opened.
func checkNetworkNamespace(path string) error {
	if path == "" {
		return fmt.Errorf("the runtime does not report a network namespace")
	}
	ns, err := netns.GetFromPath(path)
	if err != nil {
		return err
	}
	return ns.Close()
}

// getPodIPs return the IPs, it tries first to use
// the existing NRI API, but since it is only available
// in containerd 2.1+ https://github.com/containerd/containerd/pull/10921
// it falls back to the network namespace
func getPodIPs(pod *nriapi.PodSandbox) []string {
	if ips := pod.GetIps(); len(ips) > 0 {
		return ips
	}
	// fallback to use the network namespace info
	ips := []string{}
	nsPath := getNetworkNamespace(pod)
	if nsPath == "" {
		return ips
	}
	sandboxNs, err := netns.GetFromPath(nsPath)
	if err != nil {
		klog.Infof("can not get network namespace %s : %v", nsPath, err)
		return ips
	}
	defer sandboxNs.Close()
	// to avoid golang problem with goroutines we create the socket in the
	// namespace and use it directly
	nhNs, err := netlink.NewHandleAt(sandboxNs)
	if err != nil {
		klog.Infof("can not get netlink handle at network namespace %s : %v", nsPath, err)
		return ips
	}
	defer nhNs.Close()

	// containerd has a convention the interface inside the Pod is always named eth0
	// internal/cri/server/helpers.go: defaultIfName = "eth0"
	nsLink, err := nhNs.LinkByName("eth0")
	if err != nil {
		klog.Infof("can not get interface eth0 network namespace %s : %v", nsPath, err)
		return ips
	}
	addrs, err := nhNs.AddrList(nsLink, netlink.FAMILY_ALL)
	if err != nil {
		klog.Infof("can not get ip addresses at network namespace %s : %v", nsPath, err)
		return ips
	}
	for _, addr := range addrs {
		// ignore link local and loopback addresses
		// those are not added by the CNI
		if addr.IP.IsGlobalUnicast() {
			ips = append(ips, addr.IP.String())
		}
	}
	return ips
}
