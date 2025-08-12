package pipeline

import (
	"context"
	"net"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog/v2"
	"sigs.k8s.io/kube-network-policies/pkg/api"
	"sigs.k8s.io/kube-network-policies/pkg/network"
	npav1alpha1 "sigs.k8s.io/network-policy-api/apis/v1alpha1"
	anplisters "sigs.k8s.io/network-policy-api/pkg/client/listers/apis/v1alpha1"
)

// NewBaselineAdminNetworkPolicyEvaluator creates a new pipeline evaluator for BaselineAdminNetworkPolicies.
func NewBaselineAdminNetworkPolicyEvaluator(
	podInfoGetter PodByIPGetter,
	banpLister anplisters.BaselineAdminNetworkPolicyLister,
	nsLister corelisters.NamespaceLister,
) Evaluator {
	return Evaluator{
		Priority: 100,
		Name:     "BaselineAdminNetworkPolicy",
		Evaluate: func(ctx context.Context, p *network.Packet) (Verdict, error) {
			logger := klog.FromContext(ctx)
			srcPod, srcPodFound := podInfoGetter(p.SrcIP.String())
			dstPod, dstPodFound := podInfoGetter(p.DstIP.String())

			// Egress Evaluation
			if srcPodFound {
				allPolicies, err := banpLister.List(labels.Everything())
				if err != nil {
					return VerdictNext, err
				}
				srcPodBaselineAdminNetworkPolices := getBaselineAdminNetworkPoliciesForPod(srcPod, allPolicies)
				action := evaluateBaselineAdminEgress(ctx, srcPodBaselineAdminNetworkPolices, srcPod, dstPod, p.DstIP, int(p.DstPort), p.Proto, nsLister, podInfoGetter)
				logger.V(2).Info("Egress BaselineAdminNetworkPolicies", "npolicies", len(srcPodBaselineAdminNetworkPolices), "action", action)
				if action == npav1alpha1.BaselineAdminNetworkPolicyRuleActionDeny {
					return VerdictDeny, nil
				}
			}

			// Ingress Evaluation
			if dstPodFound {
				allPolicies, err := banpLister.List(labels.Everything())
				if err != nil {
					return VerdictNext, err
				}
				dstPodBaselineAdminNetworkPolices := getBaselineAdminNetworkPoliciesForPod(dstPod, allPolicies)
				action := evaluateBaselineAdminIngress(ctx, dstPodBaselineAdminNetworkPolices, dstPod, srcPod, p.SrcIP, int(p.SrcPort), p.Proto, nsLister, podInfoGetter)
				logger.V(2).Info("Ingress BaselineAdminNetworkPolicies", "npolicies", len(dstPodBaselineAdminNetworkPolices), "action", action)
				if action == npav1alpha1.BaselineAdminNetworkPolicyRuleActionDeny {
					return VerdictDeny, nil
				}
				if action == npav1alpha1.BaselineAdminNetworkPolicyRuleActionAllow {
					return VerdictNext, nil
				}
			}

			return VerdictNext, nil
		},
	}
}

func getBaselineAdminNetworkPoliciesForPod(pod *api.PodInfo, allBANPs []*npav1alpha1.BaselineAdminNetworkPolicy) []*npav1alpha1.BaselineAdminNetworkPolicy {
	var matchingBANPs []*npav1alpha1.BaselineAdminNetworkPolicy
	if pod == nil || pod.Namespace == nil {
		return matchingBANPs
	}
	for _, banp := range allBANPs {
		selector, err := metav1.LabelSelectorAsSelector(&banp.Spec.Subject)
		if err != nil {
			continue
		}
		if selector.Matches(labels.Set(pod.Namespace.Labels)) {
			matchingBANPs = append(matchingBANPs, banp)
		}
	}
	return matchingBANPs
}

func evaluateBaselineAdminEgress(ctx context.Context, policies []*npav1alpha1.BaselineAdminNetworkPolicy, srcPod, dstPod *api.PodInfo, dstIP net.IP, dstPort int, protocol v1.Protocol, nsLister anplisters.NamespaceLister, podInfoGetter PodByIPGetter) npav1alpha1.BaselineAdminNetworkPolicyRuleAction {
	// Default action is Allow
	finalAction := npav1alpha1.BaselineAdminNetworkPolicyRuleActionAllow
	for _, policy := range policies {
		for _, rule := range policy.Spec.Egress {
			if matchesBaselineAdminEgressRule(ctx, &rule, srcPod, dstPod, dstIP, dstPort, protocol, nsLister, podInfoGetter) {
				if rule.Action == npav1alpha1.BaselineAdminNetworkPolicyRuleActionDeny {
					return npav1alpha1.BaselineAdminNetworkPolicyRuleActionDeny
				}
			}
		}
	}
	return finalAction
}

func evaluateBaselineAdminIngress(ctx context.Context, policies []*npav1alpha1.BaselineAdminNetworkPolicy, dstPod, srcPod *api.PodInfo, srcIP net.IP, srcPort int, protocol v1.Protocol, nsLister anplisters.NamespaceLister, podInfoGetter PodByIPGetter) npav1alpha1.BaselineAdminNetworkPolicyRuleAction {
	// Default action is Allow
	finalAction := npav1alpha1.BaselineAdminNetworkPolicyRuleActionAllow
	for _, policy := range policies {
		for _, rule := range policy.Spec.Ingress {
			if matchesBaselineAdminIngressRule(ctx, &rule, dstPod, srcPod, srcIP, srcPort, protocol, nsLister, podInfoGetter) {
				if rule.Action == npav1alpha1.BaselineAdminNetworkPolicyRuleActionDeny {
					return npav1alpha1.BaselineAdminNetworkPolicyRuleActionDeny
				}
			}
		}
	}
	return finalAction
}
