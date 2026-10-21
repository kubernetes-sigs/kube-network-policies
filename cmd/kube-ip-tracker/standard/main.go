/*
Copyright 2025 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"reflect"
	"sync"
	"sync/atomic"
	"syscall"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"

	"sigs.k8s.io/kube-network-policies/pkg/api"
	"sigs.k8s.io/kube-network-policies/pkg/ipcache"
)

var (
	listenAddr = flag.String("listen-address", "http://0.0.0.0:19090", "The address for the cache server to listen on.")
	kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	etcdDir    = flag.String("etcd-dir", "./ipcache.etcd", "The directory for the embedded etcd server.")
	caFile     = flag.String("tls-ca-file", "", "The CA file for the server.")
	certFile   = flag.String("tls-cert-file", "", "The certificate file for the server.")
	keyFile    = flag.String("tls-key-file", "", "The key file for the server.")
	clusterID  string // uses the kube-system uid as clusterId
	ready      atomic.Bool
)

func main() {
	klog.InitFlags(nil)
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, "Usage: kube-ip-tracker [options]\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	flag.VisitAll(func(f *flag.Flag) {
		klog.Infof("FLAG: --%s=%q", f.Name, f.Value)
	})

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Start the IPCache Server, which will serve the data collected by this tracker.
	if err := os.MkdirAll(*etcdDir, 0700); err != nil {
		klog.Fatalf("Failed to create etcd directory: %v", err)
	}
	var opts []ipcache.EtcdOption
	if *caFile != "" && *certFile != "" && *keyFile != "" {
		opts = append(opts, ipcache.WithTLS(*certFile, *keyFile, *caFile))
	}
	cacheServer, err := ipcache.NewEtcdStore(*listenAddr, *etcdDir, opts...)
	if err != nil {
		klog.Fatalf("Failed to create ipcache server: %v", err)
	}

	var config *rest.Config
	if *kubeconfig != "" {
		config, err = clientcmd.BuildConfigFromFlags("", *kubeconfig)
	} else {
		// creates the in-cluster config
		config, err = rest.InClusterConfig()
	}
	if err != nil {
		klog.Fatalf("can not create client-go configuration: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		klog.Fatalf("Failed to create clientset: %v", err)
	}

	factory := informers.NewSharedInformerFactory(clientset, 0)
	podInformer := factory.Core().V1().Pods().Informer()
	nsInformer := factory.Core().V1().Namespaces().Informer()
	nodeInformer := factory.Core().V1().Nodes().Informer()

	// 3. Define event handlers that will update the cache server on every change.
	t := &tracker{
		store:     cacheServer,
		podLister: factory.Core().V1().Pods().Lister(),
		nsStore:   nsInformer.GetStore(),
		nodeStore: nodeInformer.GetStore(),
	}
	_, _ = podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			t.addPod(obj.(*v1.Pod))
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			t.updatePod(oldObj.(*v1.Pod), newObj.(*v1.Pod))
		},
		DeleteFunc: t.deletePod,
	})

	// When a namespace's labels change, we must re-sync all pods within it
	// to update the cached namespace labels.
	_, _ = nsInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(oldObj, newObj interface{}) {
			oldNs, newNs := oldObj.(*v1.Namespace), newObj.(*v1.Namespace)
			if reflect.DeepEqual(oldNs.Labels, newNs.Labels) {
				return
			}
			t.resyncNamespace(newNs.Name)
		},
	})

	// 4. Start informers and wait for shutdown.
	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), podInformer.HasSynced, nsInformer.HasSynced, nodeInformer.HasSynced) {
		klog.Fatal("Failed to sync informers")
	}
	// use the kube-system uid as clusterId
	if nsKubeSystem, exists, err := nsInformer.GetStore().GetByKey(metav1.NamespaceSystem); err != nil || !exists {
		klog.Fatalf("Failed to get kube-system namespace: %v", err)
	} else {
		clusterID = string(nsKubeSystem.(*v1.Namespace).UID)
	}
	ready.Store(true)
	klog.Infoln("kube-ip-tracker is running and serving the cache...")
	<-ctx.Done()
	klog.Infoln("Shutting down.")
}

// podStore is the part of the ipcache server that the tracker writes to.
type podStore interface {
	Upsert(ip string, info *api.PodInfo) error
	DeleteIfOwner(ip string, owner *api.PodInfo) error
}

// tracker keeps the ipcache server up to date with the Pods.
type tracker struct {
	store     podStore
	podLister corelisters.PodLister
	nsStore   cache.Store
	nodeStore cache.Store
	// mu serializes the writes of the pod and the namespace event handlers.
	mu sync.Mutex
}

func (t *tracker) addPod(pod *v1.Pod) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !ownsIPs(pod) {
		// The cache may still have the entries written before the pod finished.
		t.releaseIPs(pod, podIPs(pod))
		return
	}
	t.updatePodInCache(pod)
}

func (t *tracker) updatePod(oldPod, newPod *v1.Pod) {
	t.mu.Lock()
	defer t.mu.Unlock()
	// Release the IPs that the new pod does not own: the IPs it does not have
	// anymore, or all of them if it finished or it is another pod with the
	// same name.
	owned := sets.New[string]()
	if oldPod.UID == newPod.UID && ownsIPs(newPod) {
		owned.Insert(podIPs(newPod)...)
	}
	var released []string
	for _, ip := range podIPs(oldPod) {
		if !owned.Has(ip) {
			released = append(released, ip)
		}
	}
	t.releaseIPs(oldPod, released)

	if oldPod.UID != newPod.UID || !reflect.DeepEqual(oldPod.Status.PodIPs, newPod.Status.PodIPs) || !reflect.DeepEqual(oldPod.Labels, newPod.Labels) {
		t.updatePodInCache(newPod)
	}
}

func (t *tracker) deletePod(obj interface{}) {
	pod, ok := obj.(*v1.Pod)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Infof("Couldn't get object from tombstone %#v", obj)
			return
		}
		pod, ok = tombstone.Obj.(*v1.Pod)
		if !ok {
			klog.Infof("Tombstone contained object that is not a Pod: %#v", obj)
			return
		}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.releaseIPs(pod, podIPs(pod))
}

// resyncNamespace updates the cached namespace labels of the pods in the namespace.
func (t *tracker) resyncNamespace(namespace string) {
	pods, err := t.podLister.Pods(namespace).List(labels.Everything())
	if err != nil {
		klog.Infof("Error listing pods in namespace %s: %v", namespace, err)
		return
	}
	for _, pod := range pods {
		t.mu.Lock()
		// The pod may have been deleted or finished since it was listed, the
		// pod event handler releases its IPs after the lister is updated.
		if current, err := t.podLister.Pods(namespace).Get(pod.Name); err == nil {
			t.updatePodInCache(current)
		}
		t.mu.Unlock()
	}
}

// ownsIPs returns true if the IPs in the status of the pod belong to it.
func ownsIPs(pod *v1.Pod) bool {
	return !pod.Spec.HostNetwork && pod.Status.Phase != v1.PodSucceeded && pod.Status.Phase != v1.PodFailed
}

// podIPs returns the IPs in the status of the pod, host network pods use the node IPs.
func podIPs(pod *v1.Pod) []string {
	if pod.Spec.HostNetwork {
		return nil
	}
	ips := make([]string, 0, len(pod.Status.PodIPs))
	for _, podIP := range pod.Status.PodIPs {
		ips = append(ips, podIP.IP)
	}
	return ips
}

// updatePodInCache gets the required info from a pod and its namespace and upserts it into the cache.
// It must be called with t.mu held.
func (t *tracker) updatePodInCache(pod *v1.Pod) {
	// Skip host-network pods, terminal pods or pods that don't have an IP address yet.
	if !ownsIPs(pod) || len(pod.Status.PodIPs) == 0 {
		return
	}

	nsObj, exists, err := t.nsStore.GetByKey(pod.Namespace)
	if err != nil || !exists {
		klog.Infof("Warning: namespace %s for pod %s not found, cannot update cache", pod.Namespace, pod.Name)
		return
	}
	namespace := nsObj.(*v1.Namespace)
	nsLabels := namespace.Labels

	nodeLabels := map[string]string{}
	nodeObj, exists, err := t.nodeStore.GetByKey(pod.Spec.NodeName)
	if err != nil || !exists {
		klog.Infof("Warning: node %s for pod %s not found, cannot update cache", pod.Spec.NodeName, pod.Name)
	} else {
		node := nodeObj.(*v1.Node)
		nodeLabels = node.Labels
	}

	podInfo := api.NewPodInfo(pod, nsLabels, nodeLabels, clusterID)

	for _, podIP := range pod.Status.PodIPs {
		klog.V(2).Infof("Upserting: IP=%s Pod=%s/%s", podIP.IP, pod.Namespace, pod.Name)
		err := t.store.Upsert(podIP.IP, podInfo)
		if err != nil {
			klog.Errorf("Failed to upsert IP %s for pod %s/%s: %v", podIP.IP, pod.Namespace, pod.Name, err)
		}
	}
}

// releaseIPs deletes the entries of the IPs that still belong to the pod, the
// IPs may have been assigned to another pod. It must be called with t.mu held.
func (t *tracker) releaseIPs(pod *v1.Pod, ips []string) {
	owner := &api.PodInfo{Name: pod.Name, Namespace: &api.Namespace{Name: pod.Namespace}, Uid: string(pod.UID)}
	for _, ip := range ips {
		klog.V(2).Infof("Releasing: IP=%s Pod=%s/%s", ip, pod.Namespace, pod.Name)
		if err := t.store.DeleteIfOwner(ip, owner); err != nil {
			klog.Errorf("Failed to release IP %s for pod %s/%s: %v", ip, pod.Namespace, pod.Name, err)
		}
	}
}
