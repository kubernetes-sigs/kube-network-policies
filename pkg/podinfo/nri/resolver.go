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
	coreinformers "k8s.io/client-go/informers/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog/v2"
	"sigs.k8s.io/kube-network-policies/pkg/api"
	"sigs.k8s.io/kube-network-policies/pkg/podinfo"
)

var _ podinfo.IPResolver = &NRIResolver{}
var _ api.PodInfoProvider = &NRIResolver{}

// NRIResolver is a standalone component that listens to NRI events
// and maintains a cache of PodInfo objects.
type NRIResolver struct {
	nodeName    string
	stub        stub.Stub
	mu          sync.Mutex
	podInfoByIP map[string]*api.PodInfo
	nsLister    corelisters.NamespaceLister
}

// NewNRIResolver creates a new resolver that looks up pods via the NRI plugin.
func NewNRIResolver(ctx context.Context, nodeName string, namespaceInformer coreinformers.NamespaceInformer) (*NRIResolver, error) {
	const (
		pluginName = "kube-network-policies-podip-resolver"
		pluginIdx  = "10"
	)
	p := &NRIResolver{
		nodeName:    nodeName,
		podInfoByIP: make(map[string]*api.PodInfo),
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
	p.mu.Lock()
	defer p.mu.Unlock()
	podInfo, found := p.podInfoByIP[ip]
	return podInfo, found
}

func (p *NRIResolver) Synchronize(_ context.Context, pods []*nriapi.PodSandbox, containers []*nriapi.Container) ([]*nriapi.ContainerUpdate, error) {
	klog.Infof("Synchronized state with the runtime (%d pods, %d containers)...",
		len(pods), len(containers))

	for _, pod := range pods {
		ips := getPodIPs(pod)
		podKey := fmt.Sprintf("%s/%s", pod.GetNamespace(), pod.GetName())
		klog.V(4).Infof("pod=%s netns=%s ips=%v", podKey, getNetworkNamespace(pod), ips)
		podInfo := p.getPodInfo(pod)
		for _, ip := range ips {
			p.mu.Lock()
			p.podInfoByIP[ip] = podInfo
			p.mu.Unlock()
		}
	}

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
	for _, ip := range ips {
		p.mu.Lock()
		p.podInfoByIP[ip] = podInfo
		p.mu.Unlock()
	}
	return nil
}

func (p *NRIResolver) RemovePodSandbox(_ context.Context, pod *nriapi.PodSandbox) error {
	// because of this bug in https://github.com/containerd/containerd/pull/11331
	// PodIPs may not be present, but since the pod is going to be deleted
	// we just remove it from the cache
	ips := getPodIPs(pod)
	podKey := fmt.Sprintf("%s/%s", pod.GetNamespace(), pod.GetName())
	klog.V(4).Infof("Removing Pod %s ips=%v", podKey, ips)
	for _, ip := range ips {
		p.mu.Lock()
		delete(p.podInfoByIP, ip)
		p.mu.Unlock()
	}
	return nil
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
