package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

func runNodes(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("nodes", flag.ExitOnError)
	var c commonFlags
	c.add(fs)
	count := fs.Int("count", 100, "number of fake nodes")
	prefix := fs.String("prefix", "kwok-node", "node name prefix")
	podsPerNode := fs.Int("pods-per-node", 250, "allocatable pods per fake node")
	del := fs.Bool("delete", false, "delete the fake nodes instead of creating them")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cs, err := c.client()
	if err != nil {
		return err
	}
	if *del {
		return deleteNodes(ctx, cs, *prefix)
	}
	return createNodes(ctx, cs, *prefix, *count, *podsPerNode)
}

func fakeNode(name string, podsPerNode int) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Annotations: map[string]string{
				"node.alpha.kubernetes.io/ttl": "0",
				"kwok.x-k8s.io/node":           "fake",
			},
			Labels: map[string]string{
				"beta.kubernetes.io/arch":       "amd64",
				"beta.kubernetes.io/os":         "linux",
				"kubernetes.io/arch":            "amd64",
				"kubernetes.io/hostname":        name,
				"kubernetes.io/os":              "linux",
				"kubernetes.io/role":            "agent",
				"node-role.kubernetes.io/agent": "",
				"type":                          fakeNodeType,
				labelManaged:                    "true",
			},
		},
		Spec: corev1.NodeSpec{
			// Keeps real Pods (DUT agents, probes) off fake nodes.
			Taints: []corev1.Taint{{Key: fakeTaintKey, Value: "fake", Effect: corev1.TaintEffectNoSchedule}},
		},
		Status: corev1.NodeStatus{
			Allocatable: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("32"),
				corev1.ResourceMemory: resource.MustParse("256Gi"),
				corev1.ResourcePods:   *resource.NewQuantity(int64(podsPerNode), resource.DecimalSI),
			},
			Capacity: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("32"),
				corev1.ResourceMemory: resource.MustParse("256Gi"),
				corev1.ResourcePods:   *resource.NewQuantity(int64(podsPerNode), resource.DecimalSI),
			},
			NodeInfo: corev1.NodeSystemInfo{
				Architecture:    "amd64",
				OperatingSystem: "linux",
				KubeletVersion:  "fake",
			},
			Phase: corev1.NodeRunning,
		},
	}
}

func createNodes(ctx context.Context, cs kubernetes.Interface, prefix string, count, podsPerNode int) error {
	start := time.Now()
	created := 0
	for i := 0; i < count; i++ {
		name := fmt.Sprintf("%s-%d", prefix, i)
		_, err := cs.CoreV1().Nodes().Create(ctx, fakeNode(name, podsPerNode), metav1.CreateOptions{})
		switch {
		case err == nil:
			created++
		case apierrors.IsAlreadyExists(err):
		default:
			return fmt.Errorf("creating node %s: %w", name, err)
		}
	}
	klog.InfoS("fake nodes ready", "created", created, "total", count, "elapsed", time.Since(start).Round(time.Millisecond))
	return waitNodesReady(ctx, cs, count)
}

func waitNodesReady(ctx context.Context, cs kubernetes.Interface, want int) error {
	sel := fmt.Sprintf("type=%s,%s=true", fakeNodeType, labelManaged)
	for {
		list, err := cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{LabelSelector: sel})
		if err != nil {
			return err
		}
		ready := 0
		for i := range list.Items {
			for _, c := range list.Items[i].Status.Conditions {
				if c.Type == corev1.NodeReady && c.Status == corev1.ConditionTrue {
					ready++
					break
				}
			}
		}
		if ready >= want {
			klog.InfoS("fake nodes Ready", "ready", ready)
			return nil
		}
		klog.V(1).InfoS("waiting for fake nodes", "ready", ready, "want", want)
		if err := sleepCtx(ctx, 2*time.Second); err != nil {
			return err
		}
	}
}

func deleteNodes(ctx context.Context, cs kubernetes.Interface, prefix string) error {
	sel := fmt.Sprintf("type=%s,%s=true", fakeNodeType, labelManaged)
	err := cs.CoreV1().Nodes().DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{LabelSelector: sel})
	if err != nil {
		return fmt.Errorf("deleting fake nodes: %w", err)
	}
	klog.InfoS("fake nodes deleted", "prefix", prefix)
	return nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
