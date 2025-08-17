package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/apimachinery/pkg/api/meta"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/component-base/logs"
	logsapi "k8s.io/component-base/logs/api/v1"
	_ "k8s.io/component-base/logs/json/register"
	nodeutil "k8s.io/component-helpers/node/util"
	"k8s.io/klog/v2"

	"sigs.k8s.io/kube-network-policies/pkg/api"
	"sigs.k8s.io/kube-network-policies/pkg/dataplane"
	"sigs.k8s.io/kube-network-policies/pkg/dns"
	"sigs.k8s.io/kube-network-policies/pkg/networkpolicy"
	"sigs.k8s.io/kube-network-policies/pkg/plugin"
	"sigs.k8s.io/kube-network-policies/pkg/podinfo"
)

const (
	// LoggingPolicyPriority ensures the logging evaluator runs first for observability.
	LoggingPolicyPriority = -100
	// StandardNetworkPolicyPriority provides a fixed, stable anchor for the pipeline.
	// Negative priority plugins run before it; positive priority plugins run after.
	StandardNetworkPolicyPriority = 0
)

var (
	failOpen            bool
	queueID             int
	metricsBindAddress  string
	hostnameOverride    string
	netfilterBug1766Fix bool
	disableNRI          bool
	pluginDir           string
)

func init() {
	flag.BoolVar(&failOpen, "fail-open", false, "If set, don't drop packets if the controller is not running")
	flag.IntVar(&queueID, "nfqueue-id", 100, "Number of the nfqueue used")
	flag.StringVar(&metricsBindAddress, "metrics-bind-address", ":9080", "The IP address and port for the metrics server to serve on")
	flag.StringVar(&hostnameOverride, "hostname-override", "", "If non-empty, will be used as the name of the Node that kube-network-policies is running on.")
	flag.BoolVar(&netfilterBug1766Fix, "netfilter-bug-1766-fix", true, "If set, process DNS packets on the PREROUTING hooks to avoid conntrack race conditions (not needed for kernels 6.12+).")
	flag.BoolVar(&disableNRI, "disable-nri", false, "If set, disable NRI for Pod IP resolution.")
	flag.StringVar(&pluginDir, "plugin-dir", "", "Directory to load policy evaluator plugins from. If empty, only built-in policies are used.")

	flag.Usage = func() {
		fmt.Fprint(os.Stderr, "Usage: kube-network-policies [options]\n\n")
		flag.PrintDefaults()
	}
}

// PrioritizedEvaluator pairs an evaluator with its priority for sorting the pipeline.
type PrioritizedEvaluator struct {
	Priority  int
	Evaluator api.PolicyEvaluator
}

// This is a pattern to ensure that deferred functions execute before os.Exit
func main() {
	os.Exit(run())
}

func run() int {
	c := logsapi.NewLoggingConfiguration()
	logsapi.AddGoFlags(c, flag.CommandLine)
	flag.Parse()
	logs.InitLogs()
	if err := logsapi.ValidateAndApply(c, nil); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	logger := klog.FromContext(ctx)

	logger.Info("Starting kube-network-policies", "args", os.Args)
	flag.VisitAll(func(f *flag.Flag) {
		logger.Info("Flag", "name", f.Name, "value", f.Value)
	})

	nodeName, err := nodeutil.GetHostname(hostnameOverride)
	if err != nil {
		klog.Fatalf("Cannot obtain node name: %v", err)
	}

	config, err := rest.InClusterConfig()
	if err != nil {
		klog.Fatalf("Failed to get in-cluster config: %v", err)
	}
	// pass the origin config to the plugins since we are going to modify it
	// to use protobuf for efficiency, but this only works for core types.
	pluginConfig := config
	config.AcceptContentTypes = "application/vnd.kubernetes.protobuf,application/json"
	config.ContentType = "application/vnd.kubernetes.protobuf"

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		klog.Fatalf("Failed to create clientset: %v", err)
	}

	informersFactory := informers.NewSharedInformerFactory(clientset, 0)
	podInformer := informersFactory.Core().V1().Pods()
	nsInformer := informersFactory.Core().V1().Namespaces()
	nodeInformer := informersFactory.Core().V1().Nodes()
	networkPolicyInformer := informersFactory.Networking().V1().NetworkPolicies()

	// Set memory-saving transform on the pod informer.
	if err := podInformer.Informer().SetTransform(func(obj interface{}) (interface{}, error) {
		if accessor, err := meta.Accessor(obj); err == nil {
			accessor.SetManagedFields(nil)
		}
		return obj, nil
	}); err != nil {
		klog.Fatalf("Failed to set pod informer transform: %v", err)
	}

	// Prepare for lazy initialization of the DomainResolver.
	var domainResolver api.DomainResolver
	var domainResolverOnce sync.Once

	getDomainResolver := func() api.DomainResolver {
		domainResolverOnce.Do(func() {
			klog.Info("A plugin has requested a DomainResolver, starting the DNS cache.")
			domainCache := dns.NewDomainCache(queueID + 1)
			go func() {
				if err := domainCache.Run(ctx); err != nil {
					klog.Errorf("Domain cache controller exited with error: %v", err)
				}
			}()
			domainResolver = domainCache
		})
		return domainResolver
	}

	dependencies := map[string]interface{}{
		"kubeConfig":            pluginConfig,
		"getDomainResolverFunc": getDomainResolver,
	}

	// --- Pipeline Construction ---
	var evaluatorsWithPriority []PrioritizedEvaluator

	//  Add built-in evaluators.
	if klog.V(2).Enabled() {
		evaluatorsWithPriority = append(evaluatorsWithPriority, PrioritizedEvaluator{
			Priority:  LoggingPolicyPriority,
			Evaluator: networkpolicy.NewLoggingPolicy(),
		})
	}
	standardNPEvaluator := networkpolicy.NewStandardNetworkPolicy(
		nodeName, nsInformer, podInformer, networkPolicyInformer,
	)
	evaluatorsWithPriority = append(evaluatorsWithPriority, PrioritizedEvaluator{
		Priority:  StandardNetworkPolicyPriority,
		Evaluator: standardNPEvaluator,
	})

	//  Load dynamic plugins from the specified directory.
	if pluginDir != "" {
		loadedPlugins, err := plugin.LoadPlugins(pluginDir, dependencies)
		if err != nil {
			klog.Fatalf("Failed to load plugins from %s: %v", pluginDir, err)
		}
		for _, p := range loadedPlugins {
			evaluatorsWithPriority = append(evaluatorsWithPriority, PrioritizedEvaluator{
				Priority:  p.Index,
				Evaluator: p.Evaluator,
			})
		}
	}

	// Sort the entire pipeline by priority (lower number means higher priority).
	sort.Slice(evaluatorsWithPriority, func(i, j int) bool {
		return evaluatorsWithPriority[i].Priority < evaluatorsWithPriority[j].Priority
	})

	// Build the final, ordered slice of evaluators for the policy engine.
	finalEvaluators := make([]api.PolicyEvaluator, len(evaluatorsWithPriority))
	logger.Info("Initialized policy evaluation pipeline with the following order:")
	for i, pe := range evaluatorsWithPriority {
		finalEvaluators[i] = pe.Evaluator
		logger.Info("Pipeline Stage", "priority", pe.Priority, "evaluator", pe.Evaluator.Name())
	}

	// --- Pod Info Provider Setup ---
	var resolvers []podinfo.IPResolver
	informerResolver, err := podinfo.NewInformerResolver(podInformer.Informer())
	if err != nil {
		klog.Fatalf("Failed to create informer resolver: %v", err)
	}
	resolvers = append(resolvers, informerResolver)

	if !disableNRI {
		nriResolver, err := podinfo.NewNRIResolver(ctx)
		if err != nil {
			logger.Info("Failed to create NRI resolver, using API server information only.", "error", err)
		} else {
			resolvers = append(resolvers, nriResolver)
		}
	}
	podInfoProvider := podinfo.New(podInformer, nsInformer, nodeInformer, resolvers)

	// --- Controller and Server Startup ---
	policyEngine := networkpolicy.NewPolicyEngine(podInfoProvider, finalEvaluators)
	cfg := dataplane.Config{
		FailOpen:            failOpen,
		QueueID:             queueID,
		NetfilterBug1766Fix: netfilterBug1766Fix,
	}
	networkPolicyController, err := dataplane.NewController(policyEngine, cfg)
	if err != nil {
		logger.Error(err, "Failed to create dataplane controller")
		return 1
	}

	http.Handle("/metrics", promhttp.Handler())
	go func() {
		if err := http.ListenAndServe(metricsBindAddress, nil); err != nil {
			utilruntime.HandleError(fmt.Errorf("metrics server failed: %w", err))
		}
	}()

	go func() {
		if err := networkPolicyController.Run(ctx); err != nil {
			utilruntime.HandleError(fmt.Errorf("dataplane controller failed: %w", err))
		}
	}()

	informersFactory.Start(ctx.Done())

	<-ctx.Done()
	logger.Info("Received termination signal, starting cleanup...")
	time.Sleep(5 * time.Second) // Grace period for cleanup
	logger.Info("Cleanup completed, exiting.")
	return 0
}
