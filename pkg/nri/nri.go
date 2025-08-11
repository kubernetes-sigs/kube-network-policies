// SPDX-License-Identifier: APACHE-2.0

package nri

import (
	"context"
	"fmt"
	"sync"

	nriapi "github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"k8s.io/klog/v2"
)

const (
	pluginName = "kube-network-policies"
	pluginIdx  = "10"
)

type Plugin struct {
	stub     stub.Stub
	mu       sync.Mutex
	podIPMap map[string]string // podIP : podName
}

func New() (*Plugin, error) {
	p := &Plugin{
		podIPMap: map[string]string{},
	}
	opts := []stub.Option{
		stub.WithOnClose(p.onClose),
		stub.WithPluginName(pluginName),
		stub.WithPluginIdx(pluginIdx),
	}
	stub, err := stub.New(p, opts...)
	if err != nil {
		return p, fmt.Errorf("failed to create plugin stub: %w", err)
	}
	p.stub = stub
	return p, nil
}

func (p *Plugin) Run(ctx context.Context) error {
	return p.stub.Run(ctx)
}

func (p *Plugin) GetPodFromIP(ip string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.podIPMap[ip]
}

func (p *Plugin) Synchronize(_ context.Context, pods []*nriapi.PodSandbox, containers []*nriapi.Container) ([]*nriapi.ContainerUpdate, error) {
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

func (p *Plugin) Shutdown(_ context.Context) {
	klog.Info("Runtime shutting down...")
}

func (p *Plugin) RunPodSandbox(_ context.Context, pod *nriapi.PodSandbox) error {
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

func (p *Plugin) RemovePodSandbox(_ context.Context, pod *nriapi.PodSandbox) error {
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
	return nil
}

func (p *Plugin) onClose() {
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
