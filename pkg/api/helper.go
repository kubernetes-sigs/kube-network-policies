package api

import (
	"time"

	v1 "k8s.io/api/core/v1"
)

// NewPodInfo creates a PodInfo object from a Pod and its corresponding Namespace and Node labels.
// This helper is useful for populators that have access to the full Kubernetes objects since
// contain all the necessary information for Network Policies selectors
func NewPodInfo(pod *v1.Pod, nsLabels map[string]string, nodeLabels map[string]string, clusterID string) *PodInfo {
	if pod == nil {
		return nil
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
	}
}
