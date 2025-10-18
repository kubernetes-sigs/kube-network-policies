package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"sigs.k8s.io/kube-network-policies/pkg/api"
	"sigs.k8s.io/kube-network-policies/pkg/cmd"
	"sigs.k8s.io/kube-network-policies/pkg/dataplane"
	"sigs.k8s.io/kube-network-policies/pkg/dns"
	"sigs.k8s.io/kube-network-policies/pkg/networkpolicy"
	"sigs.k8s.io/kube-network-policies/pkg/podinfo"
	pluginsnpav1alpha2 "sigs.k8s.io/kube-network-policies/plugins/npa-v1alpha2"
	npav1alpha2 "sigs.k8s.io/network-policy-api/apis/v1alpha2"
	npaclient "sigs.k8s.io/network-policy-api/pkg/client/clientset/versioned"
	npainformers "sigs.k8s.io/network-policy-api/pkg/client/informers/externalversions"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/clientcmd"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/component-base/logs"
	logsapi "k8s.io/component-base/logs/api/v1"
	_ "k8s.io/component-base/logs/json/register"
	nodeutil "k8s.io/component-helpers/node/util"
	"k8s.io/klog/v2"
)

// This is a pattern to ensure that deferred functions executes before os.Exit
func main() {
	os.Exit(run())
}

func run() int {
	// Setup logging
	logCfg := logsapi.NewLoggingConfiguration()
	logsapi.AddGoFlags(logCfg, flag.CommandLine)

	// Setup flags
	opts := cmd.NewOptions()
	opts.AddFlags(flag.CommandLine)

	flag.Parse()

	// init logging
	logs.InitLogs()
	if err := logsapi.ValidateAndApply(logCfg, nil); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}

	// Create a context for structured logging, and catch termination signals
	ctx, cancel := signal.NotifyContext(
		context.Background(), os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	logger := klog.FromContext(ctx)
	logger.Info("called", "args", flag.Args())

	flag.VisitAll(func(flag *flag.Flag) {
		logger.Info("flag", "name", flag.Name, "value", flag.Value)
	})

	if _, _, err := net.SplitHostPort(opts.MetricsBindAddress); err != nil {
		logger.Error(err, "parsing metrics bind address", "address", opts.MetricsBindAddress)
		return 1
	}

	nodeName, err := nodeutil.GetHostname(opts.HostnameOverride)
	if err != nil {
		klog.Fatalf("can not obtain the node name, use the hostname-override flag if you want to set it to a specific value: %v", err)
	}

	dpCfg := dataplane.Config{
		FailOpen:            opts.FailOpen,
		QueueID:             opts.QueueID,
		NetfilterBug1766Fix: opts.NetfilterBug1766Fix,
		StrictMode:          opts.StrictMode,
	}

	var config *rest.Config
	if opts.Kubeconfig != "" {
		config, err = clientcmd.BuildConfigFromFlags("", opts.Kubeconfig)
	} else {
		// creates the in-cluster config
		config, err = rest.InClusterConfig()
	}
	if err != nil {
		klog.Fatalf("can not create client-go configuration: %v", err)
	}

	// use protobuf for better performance at scale
	// https://kubernetes.io/docs/reference/using-api/api-concepts/#alternate-representations-of-resources
	npaConfig := config // shallow copy because  CRDs does not support proto
	config.AcceptContentTypes = "application/vnd.kubernetes.protobuf,application/json"
	config.ContentType = "application/vnd.kubernetes.protobuf"

	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	informersFactory := informers.NewSharedInformerFactory(clientset, 0)
	nsInformer := informersFactory.Core().V1().Namespaces()
	networkPolicyInfomer := informersFactory.Networking().V1().NetworkPolicies()
	podInformer := informersFactory.Core().V1().Pods()
	nodeInformer := informersFactory.Core().V1().Nodes()

	// Set the memory-saving transform function on the pod informer.
	err = podInformer.Informer().SetTransform(func(obj interface{}) (interface{}, error) {
		if accessor, err := meta.Accessor(obj); err == nil {
			accessor.SetManagedFields(nil)
		}
		return obj, nil
	})
	if err != nil {
		klog.Fatalf("Failed to set pod informer transform: %v", err)
	}

	npaClient, err := npaclient.NewForConfig(npaConfig)
	if err != nil {
		klog.Fatalf("Failed to create Network client: %v", err)
	}
	npaInformerFactory := npainformers.NewSharedInformerFactory(npaClient, 0)
	cnpInformer := npaInformerFactory.Policy().V1alpha2().ClusterNetworkPolicies()

	// Create the Pod IP resolvers.
	// First, given an IP address they return the Pod name/namespace.
	informerResolver, err := podinfo.NewInformerResolver(podInformer.Informer())
	if err != nil {
		klog.Fatalf("Failed to create informer resolver: %v", err)
	}
	resolvers := []podinfo.IPResolver{informerResolver}

	// Create an NRI Pod IP resolver if enabled, since NRI connects to the container runtime
	// the Pod and IP information is provided at the time the Pod Sandbox is created and before
	// the containers start running, so policies can be enforced without race conditions.
	if !opts.DisableNRI {
		nriIPResolver, err := podinfo.NewNRIResolver(ctx, nodeName, nil)
		if err != nil {
			klog.Infof("failed to create NRI plugin, using apiserver information only: %v", err)
		}
		resolvers = append(resolvers, nriIPResolver)
	}

	// Create the pod info provider to obtain the Pod information
	// necessary for the network policy evaluation, it uses the resolvers
	// to obtain the key (Pod name and namespace) and use the informers to obtain
	// the labels that are necessary to match the network policies.
	podInfoProvider := podinfo.NewInformerProvider(
		podInformer,
		nsInformer,
		nodeInformer,
		resolvers)

	// Create the evaluators for the Pipeline to process the packets
	// and take a network policy action. The evaluators are processed
	// by the order in the array.
	evaluators := []api.PolicyEvaluator{}

	// Logging evaluator must go first if enabled.
	if klog.V(2).Enabled() {
		evaluators = append(evaluators, networkpolicy.NewLoggingPolicy())
	}

	// Admin Network Policy need to associate IP addresses to Domains
	// NewDomainCache implements the interface DomainResolver using
	// nftables to create a cache with the resolved IP addresses from the
	// Pod domain queries.
	domainResolver := dns.NewDomainCache(opts.QueueID + 1)
	go func() {
		err := domainResolver.Run(ctx)
		if err != nil {
			klog.Infof("domain cache controller exited: %v", err)
		}
	}()

	evaluators = append(evaluators, pluginsnpav1alpha2.NewClusterNetworkPolicy(
		npav1alpha2.AdminTier,
		cnpInformer,
		domainResolver,
	))

	// Standard Network Policy goes after AdminNetworkPolicy and before BaselineAdminNetworkPolicy
	evaluators = append(evaluators, networkpolicy.NewStandardNetworkPolicy(
		nodeName,
		nsInformer,
		podInformer,
		networkPolicyInfomer,
	))

	evaluators = append(evaluators, pluginsnpav1alpha2.NewClusterNetworkPolicy(
		npav1alpha2.BaselineTier,
		cnpInformer,
		domainResolver,
	))

	informersFactory.Start(ctx.Done())
	npaInformerFactory.Start(ctx.Done())

	cmd.Start(ctx, networkpolicy.NewPolicyEngine(podInfoProvider, evaluators), dpCfg, opts.MetricsBindAddress)

	<-ctx.Done()
	logger.Info("Received termination signal, starting cleanup...")
	// grace period to cleanup resources
	time.Sleep(5 * time.Second)
	logger.Info("Cleanup completed, exiting...")
	return 0
}
