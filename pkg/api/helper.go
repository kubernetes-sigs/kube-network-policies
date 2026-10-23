package api

import (
	"time"

	v1 "k8s.io/api/core/v1"
)

// PodOwnsIPs returns true if the IPs in status.podIPs belong to the pod. A
// host-network pod reports the node IPs, and a Succeeded or Failed pod keeps
// its IPs in the status after the runtime released them, so another pod may
// own them now.
func PodOwnsIPs(pod *v1.Pod) bool {
	if pod.Spec.HostNetwork {
		return false
	}
	return pod.Status.Phase != v1.PodSucceeded && pod.Status.Phase != v1.PodFailed
}

// NewPodInfo creates a PodInfo object from a Pod and its corresponding Namespace and Node labels.
// This helper is useful for populators that have access to the full Kubernetes objects since
// contain all the necessary information for Network Policies selectors
func NewPodInfo(pod *v1.Pod, nsLabels map[string]string, nodeLabels map[string]string, clusterID string) *PodInfo {
	if pod == nil {
		return nil
	}

	ips := make([]string, 0, len(pod.Status.PodIPs))
	for _, ip := range pod.Status.PodIPs {
		ips = append(ips, ip.IP)
	}

	containerPorts := make([]*ContainerPort, 0)
	for _, container := range pod.Spec.Containers {
		for _, port := range container.Ports {
			containerPorts = append(containerPorts, &ContainerPort{
				Name:     port.Name,
				Port:     port.ContainerPort,
				Protocol: string(port.Protocol),
			})
		}
	}

	return &PodInfo{
		Name:           pod.Name,
		Labels:         pod.Labels,
		ContainerPorts: containerPorts,
		Namespace: &Namespace{
			Name:   pod.Namespace,
			Labels: nsLabels,
		},
		Node: &Node{
			Name:   pod.Spec.NodeName,
			Labels: nodeLabels,
		},
		ClusterId:   clusterID,
		LastUpdated: time.Now().Unix(), // TODO: maybe get it from the managedFields metadata
		IPs:         ips,
	}
}
