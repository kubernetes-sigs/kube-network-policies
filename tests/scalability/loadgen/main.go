// loadgen drives the scalability framework's synthetic workload against a
// kind+kwok cluster: fake nodes, fake Pods spread over a controlled number of
// distinct label identities, and steady-state churn with either reused or
// fresh identities. It creates Pods directly (no ReplicaSets) at a fixed
// rate so achieved Pods/s is a parameter, not an outcome.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
)

const (
	// Labels shared by every fake Pod so scenarios can select them.
	labelGroup    = "group"
	groupSandbox  = "sandbox"
	labelIdentity = "identity"
	labelManaged  = "scale.knp.x-k8s.io/managed"

	fakeNodeType = "kwok"
	fakeTaintKey = "kwok.x-k8s.io/node"
)

func main() {
	klog.InitFlags(nil)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	var err error
	switch os.Args[1] {
	case "nodes":
		err = runNodes(ctx, os.Args[2:])
	case "pods":
		err = runPods(ctx, os.Args[2:])
	case "churn":
		err = runChurn(ctx, os.Args[2:])
	case "wait":
		err = runWait(ctx, os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		klog.ErrorS(err, "loadgen failed")
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `usage: loadgen <command> [flags]

commands:
  nodes   create or delete kwok fake nodes
  pods    create or delete fake Pods across N identities at a fixed rate
  churn   replace Pods at a fixed rate with reused or fresh identities
  wait    block until all managed Pods are Running

run 'loadgen <command> -h' for flags.
`)
}

// commonFlags are shared by every subcommand.
type commonFlags struct {
	kubeconfig string
	context    string
	qps        float64
	burst      int
}

func (c *commonFlags) add(fs *flag.FlagSet) {
	fs.StringVar(&c.kubeconfig, "kubeconfig", "", "path to kubeconfig; empty uses $KUBECONFIG or ~/.kube/config, then in-cluster")
	fs.StringVar(&c.context, "context", "", "kubeconfig context to use; empty uses the current context")
	fs.Float64Var(&c.qps, "client-qps", 500, "client-go rate limit; the create rate is bounded separately by --rate")
	fs.IntVar(&c.burst, "client-burst", 1000, "client-go burst")
}

func (c *commonFlags) client() (kubernetes.Interface, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if c.kubeconfig != "" {
		rules.ExplicitPath = c.kubeconfig
	}
	overrides := &clientcmd.ConfigOverrides{CurrentContext: c.context}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides).ClientConfig()
	if err != nil {
		if c.context != "" {
			return nil, fmt.Errorf("building client config for context %q: %w", c.context, err)
		}
		if cfg, err = rest.InClusterConfig(); err != nil {
			return nil, fmt.Errorf("building client config: %w", err)
		}
	}
	cfg.QPS = float32(c.qps)
	cfg.Burst = c.burst
	cfg.AcceptContentTypes = "application/vnd.kubernetes.protobuf,application/json"
	cfg.ContentType = "application/vnd.kubernetes.protobuf"
	return kubernetes.NewForConfig(cfg)
}
