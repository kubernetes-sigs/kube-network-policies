package podinfo

import (
	"context"
	"fmt"
	"sync"
	"time"

	nriapi "github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

// IPResolver defines an interface for resolving an IP address to a pod's key ("namespace/name").
type IPResolver interface {
	// LookupPod abstracts the logic of finding a pod's key given its IP.
	// It returns the key and true if found, otherwise an empty string and false.
	LookupPod(ip string) (string, bool)
}

// --- Informer-based Resolver ---

const (
	// PodIPIndex is the name of the indexer that maps pod IPs to pod objects.
	PodIPIndex = "podIPKeyIndex"
)

// InformerResolver is an implementation of Resolver that uses a pod informer index.
type InformerResolver struct {
	podIndexer cache.Indexer
}

// NewInformerResolver creates a new resolver that looks up pods in a Kubernetes informer.
func NewInformerResolver(podInformer cache.SharedIndexInformer) (*InformerResolver, error) {
	// Add the IP indexer to the pod informer.
	err := podInformer.AddIndexers(cache.Indexers{
		PodIPIndex: func(obj interface{}) ([]string, error) {
			pod, ok := obj.(*v1.Pod)
			if !ok || pod.Spec.HostNetwork {
				return []string{}, nil
			}
			ips := make([]string, 0, len(pod.Status.PodIPs))
			for _, ip := range pod.Status.PodIPs {
				ips = append(ips, ip.IP)
			}
			return ips, nil
		},
	})
	if err != nil {
		return nil, err
	}

	return &InformerResolver{
		podIndexer: podInformer.GetIndexer(),
	}, nil
}

// LookupPod implements the Resolver interface using the informer's index.
func (r *InformerResolver) LookupPod(ip string) (string, bool) {
	objs, err := r.podIndexer.ByIndex(PodIPIndex, ip)
	if err != nil || len(objs) == 0 {
		return "", false
	}
	// Prefer a running pod if multiple pods share the same IP.
	for _, obj := range objs {
		if pod, ok := obj.(*v1.Pod); ok && pod.Status.Phase == v1.PodRunning {
			key, err := cache.MetaNamespaceKeyFunc(pod)
			if err == nil {
				return key, true
			}
		}
	}
	// Fallback to the first pod found.
	key, err := cache.MetaNamespaceKeyFunc(objs[0])
	if err != nil {
		return "", false
	}
	return key, true
}

// --- NRI-based Resolver ---

// NRIResolver is an implementation of Resolver that uses an NRI plugin.
type NRIResolver struct {
	stub     stub.Stub
	mu       sync.Mutex
	podIPMap map[string]string // podIP : podName
}

// NewNRIResolver creates a new resolver that looks up pods via the NRI plugin.
func NewNRIResolver(ctx context.Context) (*NRIResolver, error) {
	const (
		pluginName = "kube-network-policies-podip-resolver"
		pluginIdx  = "10"
	)
	p := &NRIResolver{
		podIPMap: map[string]string{},
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

	// retry only for a maximum amount of time
	go func() {
		maxRetries := 10
		for maxRetries > 0 {
			select {
			case <-ctx.Done():
				return
			default:
			}
			err := p.Run(ctx)
			if err != nil {
				klog.Infof("nri plugin exited: %v", err)
			}
			maxRetries--
			time.Sleep(5 * time.Second)
		}
	}()

	return p, nil
}

// LookupPod implements the Resolver interface using the NRI plugin.
func (r *NRIResolver) LookupPod(ip string) (string, bool) {
	podKey := r.GetPodFromIP(ip)
	if podKey == "" {
		return "", false
	}
	return podKey, true
}

func (p *NRIResolver) Run(ctx context.Context) error {
	return p.stub.Run(ctx)
}

func (p *NRIResolver) GetPodFromIP(ip string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.podIPMap[ip]
}

func (p *NRIResolver) Synchronize(_ context.Context, pods []*nriapi.PodSandbox, containers []*nriapi.Container) ([]*nriapi.ContainerUpdate, error) {
	klog.Infof("Synchronized state with the runtime (%d pods, %d containers)...",
		len(pods), len(containers))

	for _, pod := range pods {
		ips := getPodIPs(pod)
		podKey := fmt.Sprintf("%s/%s", pod.GetNamespace(), pod.GetName())
		klog.V(4).Infof("pod=%s netns=%s ips=%v", podKey, getNetworkNamespace(pod), ips)
		for _, ip := range ips {
			p.mu.Lock()
			p.podIPMap[ip] = podKey
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
	for _, ip := range ips {
		p.mu.Lock()
		p.podIPMap[ip] = podKey
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
		delete(p.podIPMap, ip)
		p.mu.Unlock()
	}
	// remove also the pod from the cache in case the logic for IPs fails
	// There are no expected to be more than 128 or 255 pods per node
	p.mu.Lock()
	for ip, v := range p.podIPMap {
		if v == podKey {
			delete(p.podIPMap, ip)
		}
	}
	p.mu.Unlock()
	return nil
}

func (p *NRIResolver) onClose() {
	klog.Infof("Connection to the runtime lost, exiting...")
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
