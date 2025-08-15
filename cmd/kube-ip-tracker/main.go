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
	"sync/atomic"
	"syscall"
	"time"

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
	listenAddr = flag.String("listen-addr", "http://0.0.0.0:19090", "The address for the cache server to listen on.")
	kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")

	clusterID string // uses the kube-system uid as clusterId
	ready     atomic.Bool
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

	// 1. Start the IPCache Server, which will serve the data collected by this tracker.
	cacheServer, err := ipcache.NewEtcdStore(*listenAddr, "./ipcache.etcd")
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

	// 3. Define event handlers that will update the cache server on every change.
	_, _ = podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod := obj.(*v1.Pod)
			updatePodInCache(cacheServer, nsInformer.GetStore(), pod)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			pod := newObj.(*v1.Pod)
			updatePodInCache(cacheServer, nsInformer.GetStore(), pod)
		},
		DeleteFunc: func(obj interface{}) {
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
			deletePodFromCache(cacheServer, pod)
		},
	})

	// When a namespace's labels change, we must re-sync all pods within it
	// to update the cached namespace labels.
	_, _ = nsInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(oldObj, newObj interface{}) {
			oldNs, newNs := oldObj.(*v1.Namespace), newObj.(*v1.Namespace)
			if oldNs.ResourceVersion == newNs.ResourceVersion {
				return
			}
			pods, err := factory.Core().V1().Pods().Lister().Pods(newNs.Name).List(labels.Everything())
			if err != nil {
				klog.Infof("Error listing pods in namespace %s: %v", newNs.Name, err)
				return
			}
			for _, pod := range pods {
				updatePodInCache(cacheServer, nsInformer.GetStore(), pod)
			}
		},
	})

	// 4. Start informers and wait for shutdown.
	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), podInformer.HasSynced, nsInformer.HasSynced) {
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

// updatePodInCache gets the required info from a pod and its namespace and upserts it into the cache.
func updatePodInCache(server *ipcache.EtcdStore, nsStore cache.Store, pod *v1.Pod) {
	// Skip host-network pods or pods that don't have an IP address yet.
	if pod.Spec.HostNetwork || len(pod.Status.PodIPs) == 0 {
		// If the pod had IPs before and now it doesn't, we should treat it as a deletion.
		deletePodFromCache(server, pod)
		return
	}

	nsObj, exists, err := nsStore.GetByKey(pod.Namespace)
	if err != nil || !exists {
		klog.Infof("Warning: namespace %s for pod %s not found, cannot update cache", pod.Namespace, pod.Name)
		return
	}
	namespace := nsObj.(*v1.Namespace)

	podInfo := &api.PodInfo{
		Name:   pod.Name,
		Labels: pod.Labels,
		Namespace: &api.Namespace{
			Name:   pod.Namespace,
			Labels: namespace.Labels,
		},
		Node: &api.Node{
			Name: pod.Spec.NodeName,
		},
		ClusterId:   clusterID,
		LastUpdated: time.Now().Unix(), // TODO: maybe get it from the managedFields metadata
	}

	for _, podIP := range pod.Status.PodIPs {
		klog.V(2).Infof("Upserting: IP=%s Pod=%s/%s", podIP.String(), pod.Namespace, pod.Name)
		err := server.Upsert(podIP.String(), podInfo)
		if err != nil {
			klog.Errorf("Failed to upsert IP %s for pod %s/%s: %v", podIP.String(), pod.Namespace, pod.Name, err)
		}
	}
}

// deletePodFromCache removes all IPs associated with a given pod from the cache.
func deletePodFromCache(server *ipcache.EtcdStore, pod *v1.Pod) {
	for _, podIP := range pod.Status.PodIPs {
		klog.V(2).Infof("Deleting: IP=%s Pod=%s/%s", podIP.String(), pod.Namespace, pod.Name)
		err := server.Delete(podIP.String())
		if err != nil {
			klog.Errorf("Failed to delete IP %s for pod %s/%s: %v", podIP.String(), pod.Namespace, pod.Name, err)
		}
	}
}
