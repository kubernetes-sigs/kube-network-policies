package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/component-base/logs"
	logsapi "k8s.io/component-base/logs/api/v1"
	_ "k8s.io/component-base/logs/json/register"
	nodeutil "k8s.io/component-helpers/node/util"
	"k8s.io/klog/v2"

	"sigs.k8s.io/kube-network-policies/pkg/api"
	"sigs.k8s.io/kube-network-policies/pkg/cmd"
	"sigs.k8s.io/kube-network-policies/pkg/dataplane"
	pkgdht "sigs.k8s.io/kube-network-policies/pkg/dht"
	"sigs.k8s.io/kube-network-policies/pkg/networkpolicy"
	"sigs.k8s.io/kube-network-policies/pkg/podinfo"
	"sigs.k8s.io/kube-network-policies/pkg/podinfo/nri"
	pluginsdht "sigs.k8s.io/kube-network-policies/plugins/dht"
)

const defaultAsyncWorkers = 16

type dhtOptions struct {
	listenAddress    string
	serviceName      string
	serviceNamespace string
	caFile           string
	certFile         string
	keyFile          string
}

func (o *dhtOptions) addFlags(fs *flag.FlagSet) {
	fs.StringVar(&o.listenAddress, "dht-listen-address", ":19091", "Address and port for the 1-hop DHT HTTP/2 server")
	fs.StringVar(&o.serviceName, "dht-service-name", "kube-network-policies-dht", "Headless Service name whose EndpointSlices define the DHT ring")
	fs.StringVar(&o.serviceNamespace, "dht-service-namespace", metav1.NamespaceSystem, "Namespace of the DHT headless Service")
	fs.StringVar(&o.caFile, "dht-ca-file", "", "CA certificate file for mutual TLS between DHT agents")
	fs.StringVar(&o.certFile, "dht-cert-file", "", "Certificate file for mutual TLS between DHT agents")
	fs.StringVar(&o.keyFile, "dht-key-file", "", "Private key file for mutual TLS between DHT agents")
}

// This is a pattern to ensure that deferred functions execute before os.Exit.
func main() {
	os.Exit(run())
}

func run() int {
	logCfg := logsapi.NewLoggingConfiguration()
	logsapi.AddGoFlags(logCfg, flag.CommandLine)

	opts := cmd.NewOptions()
	opts.AddFlags(flag.CommandLine)

	dhtOpts := &dhtOptions{}
	dhtOpts.addFlags(flag.CommandLine)

	flag.Parse()

	logs.InitLogs()
	if err := logsapi.ValidateAndApply(logCfg, nil); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}

	ctx, cancel := signal.NotifyContext(
		context.Background(), os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	logger := klog.FromContext(ctx)
	logger.Info("called", "args", flag.Args())

	flag.VisitAll(func(f *flag.Flag) {
		logger.Info("flag", "name", f.Name, "value", f.Value)
	})

	if _, _, err := net.SplitHostPort(opts.MetricsBindAddress); err != nil {
		logger.Error(err, "parsing metrics bind address", "address", opts.MetricsBindAddress)
		return 1
	}

	_, listenPortStr, err := net.SplitHostPort(dhtOpts.listenAddress)
	if err != nil {
		logger.Error(err, "parsing dht listen address", "address", dhtOpts.listenAddress)
		return 1
	}
	listenPort, err := strconv.Atoi(listenPortStr)
	if err != nil || listenPort <= 0 {
		logger.Error(err, "invalid dht listen port", "port", listenPortStr)
		return 1
	}

	nodeName, err := nodeutil.GetHostname(opts.HostnameOverride)
	if err != nil {
		logger.Error(err, "cannot obtain node name; use --hostname-override to set it")
		return 1
	}

	var serverTLS, clientTLS *tls.Config
	if dhtOpts.caFile != "" || dhtOpts.certFile != "" || dhtOpts.keyFile != "" {
		if dhtOpts.caFile == "" || dhtOpts.certFile == "" || dhtOpts.keyFile == "" {
			logger.Error(nil, "all of --dht-ca-file, --dht-cert-file, and --dht-key-file must be set together")
			return 1
		}
		serverTLS, clientTLS, err = pkgdht.NewTLSConfigs(dhtOpts.caFile, dhtOpts.certFile, dhtOpts.keyFile)
		if err != nil {
			logger.Error(err, "loading DHT mTLS configuration")
			return 1
		}
	}

	var config *rest.Config
	if opts.Kubeconfig != "" {
		config, err = clientcmd.BuildConfigFromFlags("", opts.Kubeconfig)
	} else {
		config, err = rest.InClusterConfig()
	}
	if err != nil {
		logger.Error(err, "creating client-go configuration")
		return 1
	}

	config.AcceptContentTypes = "application/vnd.kubernetes.protobuf,application/json"
	config.ContentType = "application/vnd.kubernetes.protobuf"

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		logger.Error(err, "creating Kubernetes clientset")
		return 1
	}

	// 1. Small cluster-wide informers: Namespaces and NetworkPolicies only.
	clusterInformers := informers.NewSharedInformerFactory(clientset, 0)
	nsInformer := clusterInformers.Core().V1().Namespaces()
	networkPolicyInformer := clusterInformers.Networking().V1().NetworkPolicies()

	// 2. Node-scoped Pod informer: watches ONLY pods scheduled on this node so
	// cluster pod watch fanout drops from O(nodes * pods) to O(pods).
	localPodInformers := informers.NewSharedInformerFactoryWithOptions(
		clientset,
		0,
		informers.WithTweakListOptions(func(o *metav1.ListOptions) {
			o.FieldSelector = "spec.nodeName=" + nodeName
		}),
	)
	localPodInformer := localPodInformers.Core().V1().Pods()
	if err := localPodInformer.Informer().SetTransform(func(obj any) (any, error) {
		if accessor, err := meta.Accessor(obj); err == nil {
			accessor.SetManagedFields(nil)
		}
		return obj, nil
	}); err != nil {
		logger.Error(err, "setting local pod informer transform")
		return 1
	}

	// 3. EndpointSlice informer filtered strictly to the DHT headless Service.
	epSliceInformers := informers.NewSharedInformerFactoryWithOptions(
		clientset,
		0,
		informers.WithNamespace(dhtOpts.serviceNamespace),
		informers.WithTweakListOptions(func(o *metav1.ListOptions) {
			o.LabelSelector = discoveryv1.LabelServiceName + "=" + dhtOpts.serviceName
		}),
	)
	epSliceInformer := epSliceInformers.Discovery().V1().EndpointSlices()

	dhtNode, err := pkgdht.New(pkgdht.Config{
		NodeName:      nodeName,
		ListenAddress: dhtOpts.listenAddress,
		ServerTLS:     serverTLS,
		ClientTLS:     clientTLS,
	})
	if err != nil {
		logger.Error(err, "creating DHT node")
		return 1
	}

	epSlicesSynced, err := pluginsdht.WatchEndpointSlices(ctx, dhtNode, epSliceInformer, dhtOpts.serviceNamespace, listenPort)
	if err != nil {
		logger.Error(err, "watching DHT EndpointSlices")
		return 1
	}

	var localResolver podinfo.LocalResolver
	var nriResolver *nri.NRIResolver
	if !opts.DisableNRI {
		nriResolver, err = nri.NewNRIResolver(ctx, nodeName, nsInformer)
		if err != nil {
			klog.Infof("failed to create NRI plugin, using node-scoped pod informer only: %v", err)
			nriResolver = nil
		} else {
			localResolver = nriResolver
		}
	}

	provider, err := pluginsdht.NewProvider(nodeName, localPodInformer, nsInformer, localResolver, dhtNode)
	if err != nil {
		logger.Error(err, "creating DHT pod info provider")
		return 1
	}
	if nriResolver != nil {
		// SetEventHandler replays any already-tracked sandboxes so no startup events are lost.
		nriResolver.SetEventHandler(nri.EventHandler{
			OnUpsert: provider.OnNRIUpsert,
			OnDelete: provider.OnNRIDelete,
		})
	}

	dhtDone := make(chan error, 1)
	go func() {
		dhtDone <- dhtNode.Run(ctx)
	}()

	evaluators := []api.PolicyEvaluator{}
	if klog.V(4).Enabled() {
		evaluators = append(evaluators, networkpolicy.NewLoggingPolicy())
	}
	// StandardNetworkPolicy only reads local pods from podInformer for ManagedIPs,
	// so passing localPodInformer keeps divertAll=false without any global pod watch.
	evaluators = append(evaluators, networkpolicy.NewStandardNetworkPolicy(
		nodeName,
		nsInformer,
		localPodInformer,
		networkPolicyInformer,
	))

	clusterInformers.Start(ctx.Done())
	localPodInformers.Start(ctx.Done())
	epSliceInformers.Start(ctx.Done())

	if !cache.WaitForCacheSync(ctx.Done(), epSlicesSynced) {
		logger.Error(nil, "timed out waiting for DHT EndpointSlices cache sync")
		return 1
	}

	dpCfg := dataplane.Config{
		FailOpen:            opts.FailOpen,
		QueueID:             opts.QueueID,
		NetfilterBug1766Fix: opts.NetfilterBug1766Fix,
		StrictMode:          opts.StrictMode,
		AsyncWorkers:        defaultAsyncWorkers,
	}
	cmd.Start(ctx, networkpolicy.NewPolicyEngine(provider, evaluators), dpCfg, opts)

	<-ctx.Done()
	logger.Info("Received termination signal, starting cleanup...")
	if err := <-dhtDone; err != nil {
		logger.Error(err, "DHT server exited with error")
	}
	// Grace period to let dataplane controller clean up resources.
	time.Sleep(5 * time.Second)
	logger.Info("Cleanup completed, exiting...")
	return 0
}
