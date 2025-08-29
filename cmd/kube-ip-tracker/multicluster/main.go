package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"sync"
	"syscall"

	"github.com/fsnotify/fsnotify"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"

	"sigs.k8s.io/kube-network-policies/pkg/api"
	"sigs.k8s.io/kube-network-policies/pkg/ipcache"
)

var (
	listenAddr    = flag.String("listen-address", "http://0.0.0.0:19090", "The address for the cache server to listen on.")
	kubeconfigDir = flag.String("kubeconfig-dir", "", "Directory containing kubeconfig files for clusters to watch in multi-cluster mode.")
	etcdDir       = flag.String("etcd-dir", "./ipcache.etcd", "The directory for the embedded etcd server.")
	caFile        = flag.String("tls-ca-file", "", "The CA file for the server.")
	certFile      = flag.String("tls-cert-file", "", "The certificate file for the server.")
	keyFile       = flag.String("tls-key-file", "", "The key file for the server.")

	// Global map to keep track of running cluster watchers
	clusterContexts sync.Map // map[clusterName]context.CancelFunc
)

func main() {
	klog.InitFlags(nil)
	flag.Parse()

	if *kubeconfigDir == "" {
		klog.Fatal("required --kubeconfig-dir flag")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	var opts []ipcache.EtcdOption
	if *caFile != "" && *certFile != "" && *keyFile != "" {
		opts = append(opts, ipcache.WithTLS(*certFile, *keyFile, *caFile))
	}

	// Create the etcd directory if it doesn't exist.
	if err := os.MkdirAll(*etcdDir, 0750); err != nil {
		klog.Fatalf("Failed to create etcd directory: %v", err)
	}

	cacheServer, err := ipcache.NewEtcdStore(*listenAddr, *etcdDir, opts...)
	if err != nil {
		klog.Fatalf("Failed to create ipcache server: %v", err)
	}

	go watchKubeconfigDir(ctx, *kubeconfigDir, cacheServer)

	klog.Infoln("kube-ip-tracker is running...")
	<-ctx.Done()
	klog.Infoln("Shutting down.")
}

func watchKubeconfigDir(ctx context.Context, dir string, server *ipcache.EtcdStore) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		klog.Fatalf("Failed to create file watcher: %v", err)
	}
	defer watcher.Close()

	if err := watcher.Add(dir); err != nil {
		klog.Fatalf("Failed to add directory to watcher: %v", err)
	}

	reconcile := func() {
		klog.Info("Reconciling kubeconfigs...")
		activeClusters := make(map[string]bool)

		files, _ := os.ReadDir(dir)
		for _, f := range files {
			if !f.IsDir() {
				path := filepath.Join(dir, f.Name())
				clusters, err := getClustersFromKubeconfig(path)
				if err != nil {
					klog.Errorf("Error processing kubeconfig %s: %v", path, err)
					continue
				}
				for clusterName := range clusters {
					activeClusters[clusterName] = true
					if _, loaded := clusterContexts.Load(clusterName); !loaded {
						startForKubeconfig(ctx, path, clusterName, server)
					}
				}
			}
		}

		// Stop watchers for clusters that are no longer defined
		clusterContexts.Range(func(key, value interface{}) bool {
			clusterName := key.(string)
			if !activeClusters[clusterName] {
				stopWatching(clusterName)
			}
			return true
		})
	}

	reconcile() // Initial run

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Remove) != 0 {
				reconcile()
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			klog.Errorf("Watcher error: %v", err)
		case <-ctx.Done():
			return
		}
	}
}

func startForKubeconfig(ctx context.Context, kubeconfigPath, clusterAlias string, server *ipcache.EtcdStore) {
	var config *rest.Config
	var err error

	if kubeconfigPath == "" {
		klog.Errorf("missing kubeconfig path")
		return
	}
	loadingRules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfigPath}
	configOverrides := &clientcmd.ConfigOverrides{}
	if clusterAlias != "" {
		configOverrides.CurrentContext = clusterAlias
	}
	config, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides).ClientConfig()
	if err != nil {
		klog.Errorf("Failed to create client-go configuration for %s: %v", kubeconfigPath, err)
		return
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		klog.Errorf("Failed to create clientset for %s: %v", kubeconfigPath, err)
		return
	}

	// We use the kube-system UID as the unique identifier for the cluster.
	ns, err := clientset.CoreV1().Namespaces().Get(ctx, metav1.NamespaceSystem, metav1.GetOptions{})
	if err != nil {
		klog.Errorf("Failed to get kube-system namespace to determine cluster ID for cluster %s: %v", clusterAlias, err)
		return
	}
	clusterID := string(ns.UID)

	if _, loaded := clusterContexts.Load(clusterAlias); loaded {
		klog.Infof("Already watching cluster with alias: %s", clusterAlias)
		return
	}

	clusterCtx, cancel := context.WithCancel(ctx)
	clusterContexts.Store(clusterAlias, cancel)

	factory := informers.NewSharedInformerFactory(clientset, 0)
	podInformer := factory.Core().V1().Pods().Informer()
	nsInformer := factory.Core().V1().Namespaces().Informer()
	nodeInformer := factory.Core().V1().Nodes().Informer()

	_, _ = podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			updatePodInCache(server, nsInformer.GetStore(), nodeInformer.GetStore(), obj.(*v1.Pod), clusterID)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			oldPod := oldObj.(*v1.Pod)
			newPod := newObj.(*v1.Pod)
			// check if pod IPs or labels changed
			if !reflect.DeepEqual(oldPod.Status.PodIPs, newPod.Status.PodIPs) || !reflect.DeepEqual(oldPod.Labels, newPod.Labels) {
				updatePodInCache(server, nsInformer.GetStore(), nodeInformer.GetStore(), newPod, clusterID)
			}
		},
		DeleteFunc: func(obj interface{}) { deletePodFromCache(server, obj) },
	})

	_, _ = nsInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(oldObj, newObj interface{}) {
			oldNs, newNs := oldObj.(*v1.Namespace), newObj.(*v1.Namespace)
			if reflect.DeepEqual(oldNs.Labels, newNs.Labels) {
				return
			}
			pods, err := factory.Core().V1().Pods().Lister().Pods(newNs.Name).List(labels.Everything())
			if err != nil {
				klog.Errorf("Error listing pods in namespace %s for cluster %s: %v", newNs.Name, clusterAlias, err)
				return
			}
			for _, pod := range pods {
				updatePodInCache(server, nsInformer.GetStore(), nodeInformer.GetStore(), pod, clusterID)
			}
		},
	})

	_, _ = nodeInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(oldObj, newObj interface{}) {
			oldNode, newNode := oldObj.(*v1.Node), newObj.(*v1.Node)
			if reflect.DeepEqual(oldNode.Labels, newNode.Labels) {
				return
			}
			// This is less efficient, but necessary without a nodeName index on the pod informer.
			pods, err := factory.Core().V1().Pods().Lister().List(labels.Everything())
			if err != nil {
				klog.Errorf("Error listing all pods for cluster %s: %v", clusterAlias, err)
				return
			}
			for _, pod := range pods {
				if pod.Spec.NodeName == newNode.Name {
					updatePodInCache(server, nsInformer.GetStore(), nodeInformer.GetStore(), pod, clusterID)
				}
			}
		},
	})

	factory.Start(clusterCtx.Done())
	cache.WaitForCacheSync(clusterCtx.Done(), podInformer.HasSynced, nsInformer.HasSynced, nodeInformer.HasSynced)
	klog.Infof("Started watching cluster with alias: %s", clusterAlias)
}

func stopWatching(clusterName string) {
	if cancelFunc, loaded := clusterContexts.Load(clusterName); loaded {
		cancelFunc.(context.CancelFunc)()
		clusterContexts.Delete(clusterName)
		klog.Infof("Stopped watching cluster '%s'", clusterName)
	}
}

func getClustersFromKubeconfig(path string) (map[string]bool, error) {
	config, err := clientcmd.LoadFromFile(path)
	if err != nil {
		return nil, err
	}
	clusters := make(map[string]bool)
	for name := range config.Clusters {
		clusters[name] = true
	}
	return clusters, nil
}

// updatePodInCache now accepts the cluster UID and stores it in the PodInfo.
func updatePodInCache(server *ipcache.EtcdStore, nsStore cache.Store, nodeStore cache.Store, pod *v1.Pod, clusterID string) {
	if pod.Spec.HostNetwork || len(pod.Status.PodIPs) == 0 {
		return
	}
	var nodeLabels, nsLabels map[string]string
	nsObj, exists, err := nsStore.GetByKey(pod.Namespace)
	if err == nil && exists {
		nsLabels = nsObj.(*v1.Namespace).Labels
	}
	nodeObj, exists, err := nodeStore.GetByKey(pod.Spec.NodeName)
	if err == nil && exists {
		nodeLabels = nodeObj.(*v1.Node).Labels
	}
	// The cluster UID is now stored in the ClusterId field.
	podInfo := api.NewPodInfo(pod, nsLabels, nodeLabels, clusterID)
	for _, podIP := range pod.Status.PodIPs {
		err := server.Upsert(podIP.IP, podInfo)
		if err != nil {
			klog.Errorf("fail to update IP address %s: %v", podIP.IP, err)
		}
	}
}

func deletePodFromCache(server *ipcache.EtcdStore, obj interface{}) {
	pod, ok := obj.(*v1.Pod)
	if !ok {
		if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
			pod, _ = tombstone.Obj.(*v1.Pod)
		}
	}
	if pod == nil {
		return
	}
	for _, podIP := range pod.Status.PodIPs {
		err := server.Delete(podIP.IP)
		if err != nil {
			klog.Errorf("fail to delete IP address %s: %v", podIP.IP, err)
		}
	}
}
