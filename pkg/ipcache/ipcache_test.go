/*
Copyright 2025 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package ipcache

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/testing/protocmp"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/kube-network-policies/pkg/api"
)

func TestPodAndNamespaceToPodInfo(t *testing.T) {
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "test-ns",
			Labels:    map[string]string{"app": "test"},
		},
		Spec: v1.PodSpec{
			NodeName: "test-node",
			Containers: []v1.Container{
				{
					Name: "container-1",
					Ports: []v1.ContainerPort{
						{
							Name:          "http",
							ContainerPort: 80,
							Protocol:      v1.ProtocolTCP,
						},
						{
							Name:          "metrics",
							ContainerPort: 9090,
							Protocol:      v1.ProtocolTCP,
						},
					},
				},
				{
					Name: "container-2",
					Ports: []v1.ContainerPort{
						{
							Name:          "dns",
							ContainerPort: 53,
							Protocol:      v1.ProtocolUDP,
						},
					},
				},
			},
		},
	}

	namespace := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "test-ns",
			Labels: map[string]string{"kubernetes.io/metadata.name": "test-ns"},
		},
	}

	expectedPodInfo := &api.PodInfo{
		Name:   "test-pod",
		Labels: map[string]string{"app": "test"},
		Namespace: &api.Namespace{
			Name:   "test-ns",
			Labels: map[string]string{"kubernetes.io/metadata.name": "test-ns"},
		},
		Node: &api.Node{
			Name: "test-node",
		},
		ClusterId: "test-cluster",
		ContainerPorts: []*api.ContainerPort{
			{Name: "http", Port: 80, Protocol: "TCP"},
			{Name: "metrics", Port: 9090, Protocol: "TCP"},
			{Name: "dns", Port: 53, Protocol: "UDP"},
		},
	}

	podInfo := api.NewPodInfo(pod, namespace.Labels, nil, "test-cluster")
	podInfo.LastUpdated = 0 // clear it for the comparison

	if diff := cmp.Diff(expectedPodInfo, podInfo, protocmp.Transform()); diff != "" {
		t.Errorf("PodAndNamespaceToPodInfo() mismatch (-want +got):\n%s", diff)
	}
}
