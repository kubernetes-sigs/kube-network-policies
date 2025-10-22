package cmd

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"runtime/debug"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/klog/v2"

	"sigs.k8s.io/kube-network-policies/pkg/dataplane"
	"sigs.k8s.io/kube-network-policies/pkg/networkpolicy"
)

// Options contains the common command-line options.
type Options struct {
	Kubeconfig          string
	FailOpen            bool
	QueueID             int
	MetricsBindAddress  string
	HostnameOverride    string
	NetfilterBug1766Fix bool
	DisableNRI          bool
	StrictMode          bool
}

// NewOptions creates a new Options object with default values.
func NewOptions() *Options {
	return &Options{}
}

// AddFlags adds the common flags to the provided flag set.
func (o *Options) AddFlags(fs *flag.FlagSet) {
	fs.StringVar(&o.Kubeconfig, "kubeconfig", "", "absolute path to the kubeconfig file")
	fs.BoolVar(&o.FailOpen, "fail-open", true, "If set, don't drop packets if the controller is not running")
	fs.IntVar(&o.QueueID, "nfqueue-id", 100, "Number of the nfqueue used")
	fs.StringVar(&o.MetricsBindAddress, "metrics-bind-address", ":9080", "The IP address and port for the metrics server to serve on")
	fs.StringVar(&o.HostnameOverride, "hostname-override", "", "If non-empty, will be used as the name of the Node that kube-network-policies is running on. If unset, the node name is assumed to be the same as the node's hostname.")
	fs.BoolVar(&o.NetfilterBug1766Fix, "netfilter-bug-1766-fix", true, "If set, process DNS packets on the PREROUTING hooks to avoid the race condition on the conntrack subsystem, not needed for kernels 6.12+ (see https://bugzilla.netfilter.org/show_bug.cgi?id=1766)")
	fs.BoolVar(&o.DisableNRI, "disable-nri", false, "If set, disable NRI, that is used to get the Pod IP information directly from the runtime to avoid the race explained in https://issues.k8s.io/85966")
	fs.BoolVar(&o.StrictMode, "strict-mode", true, "If set, changes to network policies also affect established connections")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, "Usage: kube-network-policies [options]\n\n")
		fs.PrintDefaults()
	}
}

// Start starts the common application components.
func Start(ctx context.Context, policyEngine *networkpolicy.PolicyEngine, dpConfig dataplane.Config, metricsBindAddress string) {
	logger := klog.FromContext(ctx)

	printVersion()

	// Start metrics server
	http.Handle("/metrics", promhttp.Handler())
	go func() {
		err := http.ListenAndServe(metricsBindAddress, nil)
		if err != nil {
			utilruntime.HandleError(fmt.Errorf("metrics server failed: %w", err))
		}
	}()

	// Start dataplane controller
	networkPolicyController, err := dataplane.NewController(
		policyEngine,
		dpConfig,
	)
	if err != nil {
		logger.Error(err, "failed to create dataplane controller")
		// It's better to crash loud
		panic(err)
	}
	go func() {
		if err := networkPolicyController.Run(ctx); err != nil {
			utilruntime.HandleError(fmt.Errorf("dataplane controller failed: %w", err))
		}
	}()
}

func printVersion() {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	var vcsRevision, vcsTime string
	for _, f := range info.Settings {
		switch f.Key {
		case "vcs.revision":
			vcsRevision = f.Value
		case "vcs.time":
			vcsTime = f.Value
		}
	}
	klog.Infof("kube-network-policies go %s build: %s time: %s", info.GoVersion, vcsRevision, vcsTime)
}
