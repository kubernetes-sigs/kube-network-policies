package main

import (
	"context"
	"flag"
	"fmt"
	"math/rand"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"
)

// runChurn deletes a managed Pod and creates a replacement at a fixed rate.
// With --fresh-identities each replacement carries an identity label never
// used before, which separates identity churn from plain Pod churn: an
// eager engine pays per new identity, a deferred one per new Pod.
func runChurn(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("churn", flag.ExitOnError)
	var c commonFlags
	c.add(fs)
	rate := fs.Float64("rate", 20, "replacements per second")
	duration := fs.Duration("duration", 2*time.Minute, "how long to churn")
	identities := fs.Int("identities", 7, "identity space used by the initial Pods (reused when --fresh-identities=false)")
	fresh := fs.Bool("fresh-identities", false, "give every replacement a never-seen identity")
	image := fs.String("image", "fake-image", "container image name (never pulled)")
	seed := fs.Int64("seed", 1, "random seed for victim selection")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cs, err := c.client()
	if err != nil {
		return err
	}

	victims, err := listManaged(ctx, cs)
	if err != nil {
		return err
	}
	if len(victims) == 0 {
		return fmt.Errorf("no managed pods to churn")
	}
	rng := rand.New(rand.NewSource(*seed))
	nextIdentity := *identities // first fresh identity id
	ctx, cancel := context.WithTimeout(ctx, *duration)
	defer cancel()
	tick := time.NewTicker(time.Duration(float64(time.Second) / *rate))
	defer tick.Stop()
	progress := time.NewTicker(10 * time.Second)
	defer progress.Stop()

	start := time.Now()
	var replaced, failed, freshUsed int
	logFailure := func(err error, what, pod string) {
		// The duration deadline cancels in-flight requests; that is the end of
		// the run, not a replacement failure.
		if ctx.Err() != nil {
			return
		}
		failed++
		// Sporadic failures are expected under churn (victim already replaced,
		// transient API errors); surface a few, count the rest.
		if failed <= 5 {
			klog.ErrorS(err, what+" failed", "pod", pod)
		} else {
			klog.V(1).ErrorS(err, what+" failed", "pod", pod)
		}
	}
	for round := 0; ; round++ {
		select {
		case <-ctx.Done():
			el := time.Since(start)
			attempts := replaced + failed
			klog.InfoS("churn finished", "replaced", replaced, "failed", failed, "fresh_identities", freshUsed,
				"elapsed", el.Round(time.Millisecond), "achieved_rate", fmt.Sprintf("%.1f/s", float64(replaced)/el.Seconds()))
			if attempts > 0 && failed*20 > attempts {
				return fmt.Errorf("%d of %d replacements failed (>5%%)", failed, attempts)
			}
			return nil
		case <-progress.C:
			klog.InfoS("churning", "replaced", replaced, "failed", failed, "fresh_identities", freshUsed)
		case <-tick.C:
		}

		v := victims[rng.Intn(len(victims))]
		err := cs.CoreV1().Pods(v.Namespace).Delete(ctx, v.Name, metav1.DeleteOptions{GracePeriodSeconds: ptr.To[int64](0)})
		if err != nil && !apierrors.IsNotFound(err) {
			logFailure(err, "delete", v.Name)
			continue
		}
		id := rng.Intn(*identities)
		if *fresh {
			id = nextIdentity
			nextIdentity++
			freshUsed++
		}
		spec := podSpec{namespace: v.Namespace, identity: id, image: *image}
		name := fmt.Sprintf("churn-%d-%d", start.Unix(), round)
		if _, err := cs.CoreV1().Pods(v.Namespace).Create(ctx, spec.build(name), metav1.CreateOptions{}); err != nil {
			logFailure(err, "create", name)
			continue
		}
		replaced++
		// Keep the victim pool current so later rounds can replace replacements.
		victims = append(victims, podRef{Namespace: v.Namespace, Name: name})
	}
}

type podRef struct{ Namespace, Name string }

func listManaged(ctx context.Context, cs kubernetes.Interface) ([]podRef, error) {
	list, err := cs.CoreV1().Pods(metav1.NamespaceAll).List(ctx, metav1.ListOptions{LabelSelector: labelManaged + "=true"})
	if err != nil {
		return nil, err
	}
	out := make([]podRef, 0, len(list.Items))
	for i := range list.Items {
		out = append(out, podRef{Namespace: list.Items[i].Namespace, Name: list.Items[i].Name})
	}
	return out, nil
}
