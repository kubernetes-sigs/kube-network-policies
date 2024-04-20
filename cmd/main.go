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
	"sigs.k8s.io/kube-network-policies/pkg/networkpolicy"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	"golang.org/x/sys/unix"
)

var (
	failOpen           bool
	queueID            int
	metricsBindAddress string
)

func init() {
	flag.BoolVar(&failOpen, "fail-open", false, "If set, don't drop packets if the controller is not running")
	flag.IntVar(&queueID, "nfqueue-id", 100, "Number of the nfqueue used")
	flag.StringVar(&metricsBindAddress, "metrics-bind-address", ":9080", "The IP address and port for the metrics server to serve on")

	flag.Usage = func() {
		fmt.Fprint(os.Stderr, "Usage: kube-netpol [options]\n\n")
		flag.PrintDefaults()
	}
}

func main() {
	// enable logging
	klog.InitFlags(nil)
	flag.Parse()
	//
	if _, _, err := net.SplitHostPort(metricsBindAddress); err != nil {
		klog.Fatalf("error parsing metrics bind address %s : %v", metricsBindAddress, err)
	}

	cfg := networkpolicy.Config{
		FailOpen: failOpen,
		QueueID:  queueID,
	}
	// creates the in-cluster config
	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}
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

	http.Handle("/metrics", promhttp.Handler())
	go func() {
		err := http.ListenAndServe(metricsBindAddress, nil)
		utilruntime.HandleError(err)
	}()

	networkPolicyController := networkpolicy.NewController(
		clientset,
		informersFactory.Networking().V1().NetworkPolicies(),
		informersFactory.Core().V1().Namespaces(),
		informersFactory.Core().V1().Pods(),
		cfg,
	)
	go func() {
		err := networkPolicyController.Run(ctx)
		utilruntime.HandleError(err)
	}()

	informersFactory.Start(ctx.Done())

	select {
	case <-signalCh:
		klog.Infof("Exiting: received signal")
		cancel()
	case <-ctx.Done():
	}

	// grace period to cleanup resources
	time.Sleep(5 * time.Second)
}
