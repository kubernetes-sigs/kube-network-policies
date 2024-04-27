package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"sigs.k8s.io/knftables"
	"sigs.k8s.io/kube-network-policies/pkg/networkpolicy"
	npaclient "sigs.k8s.io/network-policy-api/pkg/client/clientset/versioned"
	npainformers "sigs.k8s.io/network-policy-api/pkg/client/informers/externalversions"
	"sigs.k8s.io/network-policy-api/pkg/client/informers/externalversions/apis/v1alpha1"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/informers"
	v1 "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	"golang.org/x/sys/unix"
)

var (
	failOpen                   bool
	adminNetworkPolicy         bool // 	AdminNetworkPolicy is alpha so keep it feature gated behind a flag
	baselineAdminNetworkPolicy bool // 	BaselineAdminNetworkPolicy is alpha so keep it feature gated behind a flag
	queueID                    int
	metricsBindAddress         string
)

func init() {
	flag.BoolVar(&failOpen, "fail-open", false, "If set, don't drop packets if the controller is not running")
	flag.BoolVar(&adminNetworkPolicy, "admin-network-policy", false, "If set, enable Admin Network Policy API")
	flag.BoolVar(&baselineAdminNetworkPolicy, "baseline-admin-network-policy", false, "If set, enable Baseline Admin Network Policy API")
	flag.IntVar(&queueID, "nfqueue-id", 100, "Number of the nfqueue used")
	flag.StringVar(&metricsBindAddress, "metrics-bind-address", ":9080", "The IP address and port for the metrics server to serve on")

	flag.Usage = func() {
		fmt.Fprint(os.Stderr, "Usage: kube-network-policies [options]\n\n")
		flag.PrintDefaults()
	}
}

func main() {
	// enable logging
	klog.InitFlags(nil)
	flag.Parse()

	klog.Infof("flags: %v", flag.Args())

	nft, err := knftables.New(knftables.InetFamily, "kube-network-policies")
	if err != nil {
		klog.Fatalf("Error initializing nftables: %v", err)
	}

	if _, _, err := net.SplitHostPort(metricsBindAddress); err != nil {
		klog.Fatalf("error parsing metrics bind address %s : %v", metricsBindAddress, err)
	}

	cfg := networkpolicy.Config{
		AdminNetworkPolicy:         adminNetworkPolicy,
		BaselineAdminNetworkPolicy: baselineAdminNetworkPolicy,
		FailOpen:                   failOpen,
		QueueID:                    queueID,
	}
	// creates the in-cluster config
	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
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

	// trap Ctrl+C and call cancel on the context
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	// Enable signal handler
	signalCh := make(chan os.Signal, 2)
	defer func() {
		close(signalCh)
		cancel()
	}()
	signal.Notify(signalCh, os.Interrupt, unix.SIGINT)

	informersFactory := informers.NewSharedInformerFactory(clientset, 0)

	var npaClient *npaclient.Clientset
	var npaInformerFactory npainformers.SharedInformerFactory
	var nodeInformer v1.NodeInformer
	if adminNetworkPolicy || baselineAdminNetworkPolicy {
		nodeInformer = informersFactory.Core().V1().Nodes()
		npaClient, err = npaclient.NewForConfig(npaConfig)
		if err != nil {
			klog.Fatalf("Failed to create Network client: %v", err)
		}
		npaInformerFactory = npainformers.NewSharedInformerFactory(npaClient, 0)
	}

	var anpInformer v1alpha1.AdminNetworkPolicyInformer
	if adminNetworkPolicy {
		anpInformer = npaInformerFactory.Policy().V1alpha1().AdminNetworkPolicies()
	}
	var banpInformer v1alpha1.BaselineAdminNetworkPolicyInformer
	if baselineAdminNetworkPolicy {
		banpInformer = npaInformerFactory.Policy().V1alpha1().BaselineAdminNetworkPolicies()
	}

	http.Handle("/metrics", promhttp.Handler())
	go func() {
		err := http.ListenAndServe(metricsBindAddress, nil)
		utilruntime.HandleError(err)
	}()

	networkPolicyController := networkpolicy.NewController(
		clientset,
		nft,
		informersFactory.Networking().V1().NetworkPolicies(),
		informersFactory.Core().V1().Namespaces(),
		informersFactory.Core().V1().Pods(),
		nodeInformer,
		npaClient,
		anpInformer,
		banpInformer,
		cfg,
	)
	go func() {
		err := networkPolicyController.Run(ctx)
		utilruntime.HandleError(err)
	}()

	informersFactory.Start(ctx.Done())
	if adminNetworkPolicy || baselineAdminNetworkPolicy {
		npaInformerFactory.Start(ctx.Done())
	}

	select {
	case <-signalCh:
		klog.Infof("Exiting: received signal")
		cancel()
	case <-ctx.Done():
	}

	// grace period to cleanup resources
	time.Sleep(5 * time.Second)
}
