package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"sigs.k8s.io/kube-network-policies/pkg/api"
	"sigs.k8s.io/kube-network-policies/pkg/dataplane"
	"sigs.k8s.io/kube-network-policies/pkg/nri"
	"sigs.k8s.io/kube-network-policies/pkg/pipeline"
	npaclient "sigs.k8s.io/network-policy-api/pkg/client/clientset/versioned"
	npainformers "sigs.k8s.io/network-policy-api/pkg/client/informers/externalversions"
	"sigs.k8s.io/network-policy-api/pkg/client/informers/externalversions/apis/v1alpha1"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/informers"
	coreinformers "k8s.io/client-go/informers/core/v1"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/component-base/logs"
	logsapi "k8s.io/component-base/logs/api/v1"
	_ "k8s.io/component-base/logs/json/register"
	nodeutil "k8s.io/component-helpers/node/util"
	"k8s.io/klog/v2"
)

const (
	podIPIndex = "podIPKeyIndex"
)

var (
	failOpen                   bool
	adminNetworkPolicy         bool // 	AdminNetworkPolicy is alpha so keep it feature gated behind a flag
	baselineAdminNetworkPolicy bool // 	BaselineAdminNetworkPolicy is alpha so keep it feature gated behind a flag
	queueID                    int
	metricsBindAddress         string
	hostnameOverride           string
	netfilterBug1766Fix        bool
	disableNRI                 bool
)

func init() {
	flag.BoolVar(&failOpen, "fail-open", false, "If set, don't drop packets if the controller is not running")
	flag.BoolVar(&adminNetworkPolicy, "admin-network-policy", false, "If set, enable Admin Network Policy API")
	flag.BoolVar(&baselineAdminNetworkPolicy, "baseline-admin-network-policy", false, "If set, enable Baseline Admin Network Policy API")
	flag.IntVar(&queueID, "nfqueue-id", 100, "Number of the nfqueue used")
	flag.StringVar(&metricsBindAddress, "metrics-bind-address", ":9080", "The IP address and port for the metrics server to serve on")
	flag.StringVar(&hostnameOverride, "hostname-override", "", "If non-empty, will be used as the name of the Node that kube-network-policies is running on. If unset, the node name is assumed to be the same as the node's hostname.")
	flag.BoolVar(&netfilterBug1766Fix, "netfilter-bug-1766-fix", true, "If set, process DNS packets on the PREROUTING hooks to avoid the race condition on the conntrack subsystem, not needed for kernels 6.12+ (see https://bugzilla.netfilter.org/show_bug.cgi?id=1766)")
	flag.BoolVar(&disableNRI, "disable-nri", false, "If set, disable NRI, that is used to get the Pod IP information directly from the runtime to avoid the race explained in https://issues.k8s.io/85966")

	flag.Usage = func() {
		fmt.Fprint(os.Stderr, "Usage: kube-network-policies [options]\n\n")
		flag.PrintDefaults()
	}
}

// This is a pattern to ensure that deferred functions executes before os.Exit
func main() {
	os.Exit(run())
}

func run() int {
	// Enable logging in the Kubernetes core package way (support json output)
	// https://github.com/kubernetes/component-base/tree/master
	c := logsapi.NewLoggingConfiguration()
	logsapi.AddGoFlags(c, flag.CommandLine)
	flag.Parse()
	logs.InitLogs()
	if err := logsapi.ValidateAndApply(c, nil); err != nil {
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

	if _, _, err := net.SplitHostPort(metricsBindAddress); err != nil {
		logger.Error(err, "parsing metrics bind address", "address", metricsBindAddress)
		return 1
	}

	nodeName, err := nodeutil.GetHostname(hostnameOverride)
	if err != nil {
		klog.Fatalf("can not obtain the node name, use the hostname-override flag if you want to set it to a specific value: %v", err)
	}

	cfg := dataplane.Config{
		AdminNetworkPolicy:         adminNetworkPolicy,
		BaselineAdminNetworkPolicy: baselineAdminNetworkPolicy,
		FailOpen:                   failOpen,
		QueueID:                    queueID,
		NodeName:                   nodeName,
		NetfilterBug1766Fix:        netfilterBug1766Fix,
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

	informersFactory := informers.NewSharedInformerFactory(clientset, 0)

	var npaClient *npaclient.Clientset
	var npaInformerFactory npainformers.SharedInformerFactory
	var nodeInformer coreinformers.NodeInformer
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

	nsInformer := informersFactory.Core().V1().Namespaces()
	networkPolicyInfomer := informersFactory.Networking().V1().NetworkPolicies()
	podInformer := informersFactory.Core().V1().Pods()
	podIndexer := podInformer.Informer().GetIndexer()

	// Add the IP indexer to the pod informer.
	err = podInformer.Informer().AddIndexers(cache.Indexers{
		podIPIndex: func(obj interface{}) ([]string, error) {
			pod, ok := obj.(*v1.Pod)
			if !ok || pod.Spec.HostNetwork {
				return []string{}, nil
			}
			ips := make([]string, 0, len(pod.Status.PodIPs))
			for _, ip := range pod.Status.PodIPs {
				ips = append(ips, ip.IP)
			}
			return ips, nil
		},
	})
	if err != nil {
		klog.Fatalf("Failed to add pod IP indexer: %v", err)
	}

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

	// Create the NRI plugin instance.
	var nriPlugin *nri.Plugin
	if !disableNRI {
		nriPlugin, err = nri.New()
		if err != nil {
			klog.Infof("failed to create NRI plugin, using apiserver information only: %v", err)
		} else {
			go func() {
				err := nriPlugin.Run(ctx)
				if err != nil {
					klog.Infof("nri plugin exited: %v", err)
				}
			}()
		}
	}
	// Create the getPodAssignedToIP function here, capturing the necessary variables.
	getPodAssignedToIP := func(podIP string) (*v1.Pod, bool) {
		objs, err := podIndexer.ByIndex(podIPIndex, podIP)
		if err != nil {
			return nil, false
		}
		if len(objs) == 0 && nriPlugin != nil {
			podKey := nriPlugin.GetPodFromIP(podIP)
			if podKey != "" {
				obj, ok, err := podIndexer.GetByKey(podKey)
				if err == nil && ok {
					return obj.(*v1.Pod), true
				}
			}
			return nil, false
		}
		for _, obj := range objs {
			if pod, ok := obj.(*v1.Pod); ok && pod.Status.Phase == v1.PodRunning {
				return pod, true
			}
		}
		if len(objs) > 0 {
			return objs[0].(*v1.Pod), true
		}
		return nil, false
	}

	getPodInfo := func(podIP string) (*api.PodInfo, bool) {
		pod, ok := getPodAssignedToIP(podIP)
		if !ok {
			return nil, false
		}
		var nsLabels, nodeLabels map[string]string

		if nsInformer != nil {
			ns, err := nsInformer.Lister().Get(pod.Namespace)
			if err == nil {
				nsLabels = ns.Labels
			}
		}

		if nodeInformer != nil {
			node, err := nodeInformer.Lister().Get(pod.Spec.NodeName)
			if err == nil {
				nodeLabels = node.Labels
			}
		}

		return api.NewPodInfo(pod, nsLabels, nodeLabels, ""), true
	}

	cfg.Evaluators = []pipeline.Evaluator{
		pipeline.NewLoggingEvaluator(getPodInfo),
		// ... add other evaluators, passing the getter where needed
	}

	http.Handle("/metrics", promhttp.Handler())
	go func() {
		err := http.ListenAndServe(metricsBindAddress, nil)
		utilruntime.HandleError(err)
	}()

	networkPolicyController, err := dataplane.NewController(
		clientset,
		networkPolicyInfomer,
		nsInformer,
		podInformer,
		nodeInformer,
		npaClient,
		anpInformer,
		banpInformer,
		cfg,
	)
	if err != nil {
		logger.Error(err, "Can not start network policy controller")
		return 1
	}
	go func() {
		err := networkPolicyController.Run(ctx)
		utilruntime.HandleError(err)
	}()

	informersFactory.Start(ctx.Done())
	if adminNetworkPolicy || baselineAdminNetworkPolicy {
		npaInformerFactory.Start(ctx.Done())
	}

	<-ctx.Done()
	logger.Info("Received termination signal, starting cleanup...")
	// grace period to cleanup resources
	time.Sleep(5 * time.Second)
	logger.Info("Cleanup completed, exiting...")
	return 0
}
