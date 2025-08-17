package main

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"k8s.io/client-go/rest"
	"sigs.k8s.io/kube-network-policies/pkg/api"
	"sigs.k8s.io/kube-network-policies/pkg/network"

	// The plugin now has its OWN dependency on the network-policy-api
	npaclient "sigs.k8s.io/network-policy-api/pkg/client/clientset/versioned"
	npainformers "sigs.k8s.io/network-policy-api/pkg/client/informers/externalversions"
)

// The constructor that will be loaded by the main binary
type banpPlugin struct {
	evaluator *BaselineAdminNetworkPolicy
}

func (p *banpPlugin) Name() string { return "BaselineAdminNetworkPolicyPlugin" }
func (p *banpPlugin) Ready() bool  { return p.evaluator.Ready() }
func (p *banpPlugin) EvaluateIngress(ctx context.Context, packet *network.Packet, srcPod, dstPod *api.PodInfo) (api.Verdict, error) {
	return p.evaluator.EvaluateIngress(ctx, packet, srcPod, dstPod)
}
func (p *banpPlugin) EvaluateEgress(ctx context.Context, packet *network.Packet, srcPod, dstPod *api.PodInfo) (api.Verdict, error) {
	return p.evaluator.EvaluateEgress(ctx, packet, srcPod, dstPod)
}
func (p *banpPlugin) SetDataplaneSyncCallback(syncFn api.SyncFunc) { /* No-op for this model */ }
func (p *banpPlugin) ManagedIPs(ctx context.Context) ([]netip.Addr, bool, error) {
	return p.evaluator.ManagedIPs(ctx)
}

// New is the exported entrypoint required by the plugin loader.
func New(dependencies map[string]interface{}) (api.PolicyEvaluator, error) {
	config, ok := dependencies["kubeConfig"].(*rest.Config)
	if !ok {
		return nil, fmt.Errorf("dependency 'kubeConfig' not found or has wrong type")
	}

	// Plugin creates its own client and informers
	npaClient, err := npaclient.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create NPA client: %w", err)
	}

	npaInformerFactory := npainformers.NewSharedInformerFactory(npaClient, 30*time.Minute)
	banpInformer := npaInformerFactory.Policy().V1alpha1().BaselineAdminNetworkPolicies()

	// The evaluator logic is instantiated here, inside the plugin
	anpEvaluator := NewBaselineAdminNetworkPolicy(banpInformer)

	// The plugin is responsible for starting its own informers
	go npaInformerFactory.Start(context.Background().Done()) // Use a long-lived context

	return &banpPlugin{evaluator: anpEvaluator}, nil
}
