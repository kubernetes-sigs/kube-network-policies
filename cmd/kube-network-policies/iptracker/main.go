package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	nodeutil "k8s.io/component-helpers/node/util"
	"sigs.k8s.io/kube-network-policies/pkg/api"
	"sigs.k8s.io/kube-network-policies/pkg/cmd"
	"sigs.k8s.io/kube-network-policies/pkg/dataplane"
	"sigs.k8s.io/kube-network-policies/pkg/ipcache"
	"sigs.k8s.io/kube-network-policies/pkg/networkpolicy"
	"sigs.k8s.io/kube-network-policies/pkg/podinfo"
	pluginsiptracker "sigs.k8s.io/kube-network-policies/plugins/iptracker"

	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/clientcmd"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/component-base/logs"
	logsapi "k8s.io/component-base/logs/api/v1"
	_ "k8s.io/component-base/logs/json/register"
	"k8s.io/klog/v2"
)

var (
	ipTrackerAddress  string
	ipTrackerCAFile   string
	ipTrackerCertFile string
	ipTrackerKeyFile  string
)

func init() {
	flag.StringVar(&ipTrackerAddress, "ip-tracker-address", "", "The IP address and port for the IP tracker to serve on, if empty it will use the Kubernetes API")
	flag.StringVar(&ipTrackerCAFile, "ip-tracker-ca-file", "", "The CA file for the IP tracker")
	flag.StringVar(&ipTrackerCertFile, "ip-tracker-cert-file", "", "The certificate file for the IP tracker")
	flag.StringVar(&ipTrackerKeyFile, "ip-tracker-key-file", "", "The key file for the IP tracker")

}

// This is a pattern to ensure that deferred functions executes before os.Exit
func main() {
	os.Exit(run())
}

func newTLSConfig(caFile, certFile, keyFile string) (*tls.Config, error) {
	// Load client cert
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load client key pair: %w", err)
	}

	// Load CA cert
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA file: %w", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}, nil
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

	if ipTrackerAddress == "" {
		logger.Info("ip-tracker address required")
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
	config.AcceptContentTypes = "application/vnd.kubernetes.protobuf,application/json"
	config.ContentType = "application/vnd.kubernetes.protobuf"

	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	informersFactory := informers.NewSharedInformerFactory(clientset, 0)
	networkPolicyInfomer := informersFactory.Networking().V1().NetworkPolicies()

	// Create the pod info provider to obtain the Pod information
	// necessary for the network policy evaluation, it uses the resolvers
	// to obtain the key (Pod name and namespace) and use the informers to obtain
	// the labels that are necessary to match the network policies.
	dbPath := filepath.Join(os.TempDir(), "ipcache.bolt")
	boltStore, err := ipcache.NewBoltStore(dbPath)
	if err != nil {
		klog.Fatalf("Failed to create bolt store: %v", err)
	}
	lruStore := ipcache.NewLRUStore(boltStore, 256)
	var tlsConfig *tls.Config
	if ipTrackerCAFile != "" && ipTrackerCertFile != "" && ipTrackerKeyFile != "" {
		tlsConfig, err = newTLSConfig(ipTrackerCAFile, ipTrackerCertFile, ipTrackerKeyFile)
		if err != nil {
			klog.Fatalf("Failed to create TLS config: %v", err)
		}
	}
	ipcacheClient, err := ipcache.NewClient(ctx, ipTrackerAddress, tlsConfig, lruStore, boltStore, nodeName)
	if err != nil {
		klog.Fatalf("Failed to create ipcache client: %v", err)
	}
	var podInfoProvider api.PodInfoProvider
	// Create an NRI Pod IP resolver if enabled, since NRI connects to the container runtime
	// the Pod and IP information is provided at the time the Pod Sandbox is created and before
	// the containers start running, so policies can be enforced without race conditions.
	if !opts.DisableNRI {
		nriIPResolver, err := podinfo.NewNRIResolver(ctx, nodeName, informersFactory.Core().V1().Namespaces())
		if err != nil {
			klog.Infof("failed to create NRI plugin, using apiserver information only: %v", err)
		}
		podInfoProvider = podinfo.NewFallbackPodInfoProvider(ipcacheClient, nriIPResolver)
	} else {
		podInfoProvider = ipcacheClient
	}

	// Create the evaluators for the Pipeline to process the packets
	// and take a network policy action. The evaluators are processed
	// by the order in the array.
	evaluators := []api.PolicyEvaluator{}

	// Logging evaluator must go first if enabled.
	if klog.V(2).Enabled() {
		evaluators = append(evaluators, networkpolicy.NewLoggingPolicy())
	}

	evaluators = append(evaluators, pluginsiptracker.NewIPTrackerNetworkPolicy(networkPolicyInfomer))

	informersFactory.Start(ctx.Done())

	cmd.Start(ctx, networkpolicy.NewPolicyEngine(podInfoProvider, evaluators), dpCfg, opts.MetricsBindAddress)

	<-ctx.Done()
	logger.Info("Received termination signal, starting cleanup...")
	// grace period to cleanup resources
	time.Sleep(5 * time.Second)
	logger.Info("Cleanup completed, exiting...")
	return 0
}
