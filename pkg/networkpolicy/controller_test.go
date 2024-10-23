package networkpolicy

import (
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/knftables"
	npaclientfake "sigs.k8s.io/network-policy-api/pkg/client/clientset/versioned/fake"
	npainformers "sigs.k8s.io/network-policy-api/pkg/client/informers/externalversions"
)

func makeNamespace(name string) *v1.Namespace {
	return &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"kubernetes.io/metadata.name": name,
				"a":                           "b",
			},
		},
	}
}

func makeNode(name string) *v1.Node {
	return &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"kubernetes.io/node": name,
				"a":                  "b",
			},
		},
	}
}

func makePod(name, ns string, ip string) *v1.Pod {
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			Labels: map[string]string{
				"a": "b",
			},
		},
		Spec: v1.PodSpec{
			NodeName: "testnode",
			Containers: []v1.Container{
				{
					Name:    "write-pod",
					Command: []string{"/bin/sh"},
					Ports: []v1.ContainerPort{{
						Name:          "http",
						ContainerPort: 80,
						Protocol:      v1.ProtocolTCP,
					}},
				},
			},
		},
		Status: v1.PodStatus{
			PodIPs: []v1.PodIP{
				{IP: ip},
			},
		},
	}

	return pod

}

var (
	alwaysReady = func() bool { return true }
	protocolTCP = v1.ProtocolTCP
	protocolUDP = v1.ProtocolUDP
)

type networkpolicyController struct {
	*Controller
	adminNetworkpolicyStore         cache.Store
	baselineAdminNetworkpolicyStore cache.Store
	networkpolicyStore              cache.Store
	namespaceStore                  cache.Store
	podStore                        cache.Store
	nodeStore                       cache.Store
}

func newTestController() *networkpolicyController {
	client := fake.NewSimpleClientset()
	informersFactory := informers.NewSharedInformerFactory(client, 0)

	npaClient := npaclientfake.NewSimpleClientset()
	npaInformerFactory := npainformers.NewSharedInformerFactory(npaClient, 0)

	controller, err := newController(
		client,
		knftables.NewFake(knftables.InetFamily, "kube-network-policies"),
		informersFactory.Networking().V1().NetworkPolicies(),
		informersFactory.Core().V1().Namespaces(),
		informersFactory.Core().V1().Pods(),
		informersFactory.Core().V1().Nodes(),
		npaClient,
		npaInformerFactory.Policy().V1alpha1().AdminNetworkPolicies(),
		npaInformerFactory.Policy().V1alpha1().BaselineAdminNetworkPolicies(),
		Config{
			AdminNetworkPolicy:         true,
			BaselineAdminNetworkPolicy: true,
		},
	)
	if err != nil {
		panic(err)
	}
	controller.networkpoliciesSynced = alwaysReady
	controller.namespacesSynced = alwaysReady
	controller.podsSynced = alwaysReady
	controller.nodesSynced = alwaysReady
	controller.adminNetworkPolicySynced = alwaysReady
	return &networkpolicyController{
		controller,
		npaInformerFactory.Policy().V1alpha1().AdminNetworkPolicies().Informer().GetStore(),
		npaInformerFactory.Policy().V1alpha1().BaselineAdminNetworkPolicies().Informer().GetStore(),
		informersFactory.Networking().V1().NetworkPolicies().Informer().GetStore(),
		informersFactory.Core().V1().Namespaces().Informer().GetStore(),
		informersFactory.Core().V1().Pods().Informer().GetStore(),
		informersFactory.Core().V1().Nodes().Informer().GetStore(),
	}
}

func TestConfig_Defaults(t *testing.T) {
	tests := []struct {
		name     string
		config   Config
		expected Config
	}{
		{
			name: "empty",
			config: Config{
				NodeName: "testnode", // nodename defaults to os.Hostname so we ignore for tests
			},
			expected: Config{
				FailOpen:                   false,
				AdminNetworkPolicy:         false,
				BaselineAdminNetworkPolicy: false,
				QueueID:                    100,
				NodeName:                   "testnode", // nodename defaults to os.Hostname so we ignore for tests
				NetfilterBug1766Fix:        false,
				NFTableName:                "kube-network-policies",
			},
		}, {
			name: "queue id",
			config: Config{
				NodeName: "testnode", // nodename defaults to os.Hostname so we ignore for tests
				QueueID:  99,
			},
			expected: Config{
				FailOpen:                   false,
				AdminNetworkPolicy:         false,
				BaselineAdminNetworkPolicy: false,
				QueueID:                    99,
				NodeName:                   "testnode", // nodename defaults to os.Hostname so we ignore for tests
				NetfilterBug1766Fix:        false,
				NFTableName:                "kube-network-policies",
			},
		}, {
			name: "table name",
			config: Config{
				NodeName:    "testnode", // nodename defaults to os.Hostname so we ignore for tests
				QueueID:     99,
				NFTableName: "kindnet-network-policies",
			},
			expected: Config{
				FailOpen:                   false,
				AdminNetworkPolicy:         false,
				BaselineAdminNetworkPolicy: false,
				QueueID:                    99,
				NodeName:                   "testnode", // nodename defaults to os.Hostname so we ignore for tests
				NetfilterBug1766Fix:        false,
				NFTableName:                "kindnet-network-policies",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := tt.config
			if err := c.Defaults(); err != nil {
				t.Errorf("Config.Defaults() error = %v", err)
			}

			if c != tt.expected {
				t.Errorf("Config.Defaults() = %v, want %v", c, tt.expected)
			}
		})
	}
}
