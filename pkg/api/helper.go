package api

import (
	"time"

	v1 "k8s.io/api/core/v1"
)

// PodAndNamespaceToPodInfo creates a PodInfo object from a Pod and its corresponding Namespace.
// This helper is useful for populators that have access to the full Kubernetes objects.
func PodAndNamespaceToPodInfo(pod *v1.Pod, namespace *v1.Namespace, clusterID string) *PodInfo {
	if pod == nil || namespace == nil {
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
			Labels: namespace.Labels,
		},
		Node: &Node{
			Name: pod.Spec.NodeName,
		},
		ClusterId:   clusterID,
		LastUpdated: time.Now().Unix(), // TODO: maybe get it from the managedFields metadata
	}
}

// PodAndNamespaceToPodInfo creates a PodInfo object from a Pod and its corresponding Namespace.
// This helper is useful for populators that have access to the full Kubernetes objects.
func PodAndNamespaceAndNodeToPodInfo(pod *v1.Pod, namespace *v1.Namespace, node *v1.Node, clusterID string) *PodInfo {
	if pod == nil || namespace == nil || node == nil {
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
			Labels: namespace.Labels,
		},
		Node: &Node{
			Name:   pod.Spec.NodeName,
			Labels: node.Labels,
		},
		ClusterId:   clusterID,
		LastUpdated: time.Now().Unix(), // TODO: maybe get it from the managedFields metadata
	}
}
