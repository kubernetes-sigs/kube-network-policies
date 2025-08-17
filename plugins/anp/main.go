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
type anpPlugin struct {
	evaluator *AdminNetworkPolicy
}

func (p *anpPlugin) Name() string { return "AdminNetworkPolicyPlugin" }
func (p *anpPlugin) Ready() bool  { return p.evaluator.Ready() }
func (p *anpPlugin) EvaluateIngress(ctx context.Context, packet *network.Packet, srcPod, dstPod *api.PodInfo) (api.Verdict, error) {
	return p.evaluator.EvaluateIngress(ctx, packet, srcPod, dstPod)
}
func (p *anpPlugin) EvaluateEgress(ctx context.Context, packet *network.Packet, srcPod, dstPod *api.PodInfo) (api.Verdict, error) {
	return p.evaluator.EvaluateEgress(ctx, packet, srcPod, dstPod)
}
func (p *anpPlugin) SetDataplaneSyncCallback(syncFn api.SyncFunc) { /* No-op for this model */ }
func (p *anpPlugin) ManagedIPs(ctx context.Context) ([]netip.Addr, bool, error) {
	return p.evaluator.ManagedIPs(ctx)
}

// New is the exported entrypoint required by the plugin loader.
func New(dependencies map[string]interface{}) (api.PolicyEvaluator, error) {
	config, ok := dependencies["kubeConfig"].(*rest.Config)
	if !ok {
		return nil, fmt.Errorf("dependency 'kubeConfig' not found or has wrong type")
	}

	var domainResolver api.DomainResolver
	// Check if the host provided the getter function.
	if getResolverFunc, ok := dependencies["getDomainResolverFunc"].(func() api.DomainResolver); ok {
		// This plugin needs the DomainResolver, so it calls the function to get it.
		// If this is the first plugin to call it, the resolver will be initialized.
		// Subsequent calls (from this or other plugins) will return the same instance.
		domainResolver = getResolverFunc()
	} else {
		return nil, fmt.Errorf("Host did not provide a DomainResolver. FQDN-based policies will not function.")
	}

	// Plugin creates its own client and informers
	npaClient, err := npaclient.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create NPA client: %w", err)
	}

	npaInformerFactory := npainformers.NewSharedInformerFactory(npaClient, 30*time.Minute)
	anpInformer := npaInformerFactory.Policy().V1alpha1().AdminNetworkPolicies()

	// The evaluator logic is instantiated here, inside the plugin
	anpEvaluator := NewAdminNetworkPolicy(anpInformer, domainResolver)

	// The plugin is responsible for starting its own informers
	go npaInformerFactory.Start(context.Background().Done()) // Use a long-lived context

	return &anpPlugin{evaluator: anpEvaluator}, nil
}
