package multicluster

import (
	"context"
	"fmt"
	"net"
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	networkinglisters "k8s.io/client-go/listers/networking/v1"
	"sigs.k8s.io/kube-network-policies/pkg/api"
)

// fakeNetworkPolicyLister is a mock implementation of NetworkPolicyLister for testing.
type fakeNetworkPolicyLister struct {
	policies []*networkingv1.NetworkPolicy
}

func (f *fakeNetworkPolicyLister) List(selector labels.Selector) (ret []*networkingv1.NetworkPolicy, err error) {
	return f.policies, nil
}

func (f *fakeNetworkPolicyLister) NetworkPolicies(namespace string) networkinglisters.NetworkPolicyNamespaceLister {
	return &fakeNetworkPolicyNamespaceLister{policies: f.policies, namespace: namespace}
}

// fakeNetworkPolicyNamespaceLister is a mock implementation of NetworkPolicyNamespaceLister for testing.
type fakeNetworkPolicyNamespaceLister struct {
	policies  []*networkingv1.NetworkPolicy
	namespace string
}

func (f *fakeNetworkPolicyNamespaceLister) List(selector labels.Selector) (ret []*networkingv1.NetworkPolicy, err error) {
	var policies []*networkingv1.NetworkPolicy
	for _, p := range f.policies {
		if p.Namespace == f.namespace {
			policies = append(policies, p)
		}
	}
	return policies, nil
}

func (f *fakeNetworkPolicyNamespaceLister) Get(name string) (*networkingv1.NetworkPolicy, error) {
	for _, p := range f.policies {
		if p.Namespace == f.namespace && p.Name == name {
			return p, nil
		}
	}
	return nil, fmt.Errorf("policy %s/%s not found", f.namespace, name)
}

func TestEvaluatePeer(t *testing.T) {
	tests := []struct {
		name           string
		policy         *networkingv1.NetworkPolicy
		peer           networkingv1.NetworkPolicyPeer
		peerPod        *api.PodInfo
		peerIP         net.IP
		localClusterID string
		expected       bool
	}{
		{
			name: "cross-cluster scope: allow from specific cluster with pod selector",
			policy: &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
					Annotations: map[string]string{
						ScopeAnnotation: ScopeCrossCluster,
					},
				},
			},
			peer: networkingv1.NetworkPolicyPeer{
				PodSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						ClusterNameLabel: "cluster-b",
						"app":            "client",
					},
				},
			},
			peerPod: &api.PodInfo{
				ClusterId: "cluster-b",
				Labels:    map[string]string{"app": "client"},
				Namespace: &api.Namespace{Name: "default"},
			},
			localClusterID: "cluster-a",
			expected:       true,
		},
		{
			name: "cross-cluster scope: allow from specific cluster with namespace selector",
			policy: &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
					Annotations: map[string]string{
						ScopeAnnotation: ScopeCrossCluster,
					},
				},
			},
			peer: networkingv1.NetworkPolicyPeer{
				NamespaceSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						ClusterNameLabel: "cluster-b",
						"foo":            "bar",
					},
				},
			},
			peerPod: &api.PodInfo{
				ClusterId: "cluster-b",
				Namespace: &api.Namespace{Name: "testing", Labels: map[string]string{"foo": "bar"}},
			},
			localClusterID: "cluster-a",
			expected:       true,
		},
		{
			name: "cross-cluster scope: missing cluster label should allow",
			policy: &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
					Annotations: map[string]string{
						ScopeAnnotation: ScopeCrossCluster,
					},
				},
			},
			peer: networkingv1.NetworkPolicyPeer{
				PodSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "client",
					},
				},
			},
			peerPod: &api.PodInfo{
				ClusterId: "cluster-b",
			},
			localClusterID: "cluster-a",
			expected:       true,
		},
		{
			name: "cluster-local scope: allow from local cluster",
			policy: &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
					Annotations: map[string]string{
						ScopeAnnotation: ScopeClusterLocal,
					},
				},
			},
			peer: networkingv1.NetworkPolicyPeer{
				PodSelector: &metav1.LabelSelector{},
			},
			peerPod: &api.PodInfo{
				ClusterId: "cluster-a",
				Namespace: &api.Namespace{Name: "default"},
			},
			localClusterID: "cluster-a",
			expected:       true,
		},
		{
			name: "no scope: backward compatibility - allow from remote",
			policy: &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
			},
			peer: networkingv1.NetworkPolicyPeer{
				PodSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						ClusterNameLabel: "cluster-b",
						"app":            "client",
					},
				},
			},
			peerPod: &api.PodInfo{
				ClusterId: "cluster-b",
				Labels:    map[string]string{"app": "client", ClusterNameLabel: "cluster-b"},
				Namespace: &api.Namespace{Name: "default"},
			},
			localClusterID: "cluster-a",
			expected:       true,
		},
		{
			name: "cross-cluster scope: deny from different cluster",
			policy: &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
					Annotations: map[string]string{
						ScopeAnnotation: ScopeCrossCluster,
					},
				},
			},
			peer: networkingv1.NetworkPolicyPeer{
				PodSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						ClusterNameLabel: "cluster-c",
						"app":            "client",
					},
				},
			},
			peerPod: &api.PodInfo{
				ClusterId: "cluster-b",
				Labels:    map[string]string{"app": "client"},
				Namespace: &api.Namespace{Name: "default"},
			},
			localClusterID: "cluster-a",
			expected:       false,
		},
		{
			name: "cross-cluster scope: egress to a specific cluster",
			policy: &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
					Annotations: map[string]string{
						ScopeAnnotation: ScopeCrossCluster,
					},
				},
			},
			peer: networkingv1.NetworkPolicyPeer{
				PodSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						ClusterNameLabel: "cluster-b",
						"app":            "server",
					},
				},
			},
			peerPod: &api.PodInfo{
				ClusterId: "cluster-b",
				Labels:    map[string]string{"app": "server"},
				Namespace: &api.Namespace{Name: "default"},
			},
			localClusterID: "cluster-a",
			expected:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lister := &fakeNetworkPolicyLister{policies: []*networkingv1.NetworkPolicy{tt.policy}}
			s := &MultiClusterNetworkPolicy{
				networkpolicyLister: lister,
				localClusterID:      tt.localClusterID,
			}
			if tt.peerPod != nil && tt.peerPod.Namespace == nil {
				tt.peerPod.Namespace = &api.Namespace{}
			}
			got := s.evaluatePeer(context.Background(), tt.peer, tt.peerPod, tt.peerIP, tt.policy)
			if got != tt.expected {
				t.Errorf("evaluatePeer() = %v, want %v", got, tt.expected)
			}
		})
	}
}
