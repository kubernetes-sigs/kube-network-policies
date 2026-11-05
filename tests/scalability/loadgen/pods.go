package main

import (
	"context"
	"flag"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"
)

// podSpec fixes the shape of every fake Pod: it lands only on kwok nodes and
// carries the identity label the scenarios select on.
type podSpec struct {
	namespace string
	identity  int
	image     string
}

func (p podSpec) build(name string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: p.namespace,
			Labels: map[string]string{
				labelGroup:    groupSandbox,
				labelIdentity: fmt.Sprintf("id-%d", p.identity),
				labelManaged:  "true",
			},
		},
		Spec: corev1.PodSpec{
			Affinity: &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
					NodeSelectorTerms: []corev1.NodeSelectorTerm{{
						MatchExpressions: []corev1.NodeSelectorRequirement{{
							Key: "type", Operator: corev1.NodeSelectorOpIn, Values: []string{fakeNodeType},
						}},
					}},
				},
			}},
			Tolerations: []corev1.Toleration{{
				Key: fakeTaintKey, Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule,
			}},
			TerminationGracePeriodSeconds: ptr.To[int64](0),
			Containers: []corev1.Container{{
				Name:  "sandbox",
				Image: p.image,
				Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: 80}},
			}},
		},
	}
}

func runPods(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("pods", flag.ExitOnError)
	var c commonFlags
	c.add(fs)
	count := fs.Int("count", 10000, "number of fake Pods")
	identities := fs.Int("identities", 7, "distinct identity label values; Pods are spread round-robin")
	namespaces := fs.Int("namespaces", 1, "namespaces to spread Pods across (scale-ns-<i>)")
	rate := fs.Float64("rate", 100, "Pod creations per second (0 = unbounded)")
	workers := fs.Int("workers", 32, "concurrent create requests")
	image := fs.String("image", "fake-image", "container image name (never pulled)")
	prefix := fs.String("prefix", "pod", "Pod name prefix")
	del := fs.Bool("delete", false, "delete all managed Pods and namespaces instead")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cs, err := c.client()
	if err != nil {
		return err
	}
	if *del {
		return deletePods(ctx, cs, *namespaces)
	}
	if err := ensureNamespaces(ctx, cs, *namespaces); err != nil {
		return err
	}
	specs := make([]podSpec, *count)
	for i := range specs {
		specs[i] = podSpec{
			namespace: nsName(i % *namespaces),
			identity:  i % *identities,
			image:     *image,
		}
	}
	return createPods(ctx, cs, *prefix, specs, *rate, *workers)
}

func nsName(i int) string { return fmt.Sprintf("scale-ns-%d", i) }

func ensureNamespaces(ctx context.Context, cs kubernetes.Interface, n int) error {
	for i := 0; i < n; i++ {
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
			Name:   nsName(i),
			Labels: map[string]string{labelManaged: "true", "tenant": fmt.Sprintf("t-%d", i)},
		}}
		for {
			_, err := cs.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
			if err == nil {
				break
			}
			if !apierrors.IsAlreadyExists(err) {
				return fmt.Errorf("creating namespace %s: %w", ns.Name, err)
			}
			// A previous run's cleanup may still be tearing the namespace down.
			existing, gerr := cs.CoreV1().Namespaces().Get(ctx, ns.Name, metav1.GetOptions{})
			if gerr != nil && !apierrors.IsNotFound(gerr) {
				return gerr
			}
			if gerr == nil && existing.Status.Phase != corev1.NamespaceTerminating {
				break
			}
			klog.InfoS("waiting for terminating namespace", "namespace", ns.Name)
			if err := sleepCtx(ctx, 2*time.Second); err != nil {
				return err
			}
		}
	}
	return nil
}

// createPods issues creates at the requested rate using a token ticker and a
// bounded worker pool, so the offered rate is independent of API latency.
func createPods(ctx context.Context, cs kubernetes.Interface, prefix string, specs []podSpec, rate float64, workers int) error {
	start := time.Now()
	var created, failed atomic.Int64
	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				name := fmt.Sprintf("%s-%d", prefix, i)
				_, err := cs.CoreV1().Pods(specs[i].namespace).Create(ctx, specs[i].build(name), metav1.CreateOptions{})
				switch {
				case err == nil, apierrors.IsAlreadyExists(err):
					created.Add(1)
				default:
					failed.Add(1)
					klog.V(1).ErrorS(err, "create failed", "pod", name)
				}
			}
		}()
	}

	var tick <-chan time.Time
	if rate > 0 {
		t := time.NewTicker(time.Duration(float64(time.Second) / rate))
		defer t.Stop()
		tick = t.C
	}
	progress := time.NewTicker(10 * time.Second)
	defer progress.Stop()

feed:
	for i := range specs {
		if tick != nil {
			select {
			case <-tick:
			case <-ctx.Done():
				break feed
			}
		}
		select {
		case jobs <- i:
		case <-ctx.Done():
			break feed
		}
		select {
		case <-progress.C:
			klog.InfoS("creating", "created", created.Load(), "failed", failed.Load(), "target", len(specs),
				"achieved_rate", fmt.Sprintf("%.1f/s", float64(created.Load())/time.Since(start).Seconds()))
		default:
		}
	}
	close(jobs)
	wg.Wait()
	el := time.Since(start)
	klog.InfoS("pods created", "created", created.Load(), "failed", failed.Load(), "elapsed", el.Round(time.Millisecond),
		"achieved_rate", fmt.Sprintf("%.1f/s", float64(created.Load())/el.Seconds()))
	if failed.Load() > 0 {
		return fmt.Errorf("%d pod creates failed", failed.Load())
	}
	return ctx.Err()
}

func deletePods(ctx context.Context, cs kubernetes.Interface, namespaces int) error {
	sel := labelManaged + "=true"
	for i := 0; i < namespaces; i++ {
		ns := nsName(i)
		err := cs.CoreV1().Pods(ns).DeleteCollection(ctx, metav1.DeleteOptions{GracePeriodSeconds: ptr.To[int64](0)},
			metav1.ListOptions{LabelSelector: sel})
		if err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("deleting pods in %s: %w", ns, err)
		}
	}
	klog.InfoS("managed pods deleted", "namespaces", namespaces)
	return nil
}

func runWait(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("wait", flag.ExitOnError)
	var c commonFlags
	c.add(fs)
	want := fs.Int("count", 0, "expected Running Pods; 0 waits until no managed Pod is Pending")
	timeout := fs.Duration("timeout", 10*time.Minute, "give up after this long")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cs, err := c.client()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	start := time.Now()
	for {
		running, pending, other, err := countPods(ctx, cs)
		if err != nil {
			return err
		}
		done := (*want > 0 && running >= *want) || (*want == 0 && pending == 0 && running > 0)
		if done {
			klog.InfoS("pods running", "running", running, "elapsed", time.Since(start).Round(time.Millisecond))
			return nil
		}
		klog.V(1).InfoS("waiting", "running", running, "pending", pending, "other", other)
		if err := sleepCtx(ctx, 2*time.Second); err != nil {
			return fmt.Errorf("timed out: running=%d pending=%d other=%d: %w", running, pending, other, err)
		}
	}
}

func countPods(ctx context.Context, cs kubernetes.Interface) (running, pending, other int, err error) {
	list, err := cs.CoreV1().Pods(metav1.NamespaceAll).List(ctx, metav1.ListOptions{LabelSelector: labelManaged + "=true"})
	if err != nil {
		return 0, 0, 0, err
	}
	for i := range list.Items {
		switch list.Items[i].Status.Phase {
		case corev1.PodRunning:
			running++
		case corev1.PodPending:
			pending++
		default:
			other++
		}
	}
	return running, pending, other, nil
}
