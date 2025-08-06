package networkpolicy

import (
	"context"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/vishvananda/netns"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	npaclientfake "sigs.k8s.io/network-policy-api/pkg/client/clientset/versioned/fake"
	npainformers "sigs.k8s.io/network-policy-api/pkg/client/informers/externalversions"
)

var (
	usernsEnabled bool
	checkUserns   sync.Once
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

func newTestController(config Config) *networkpolicyController {
	client := fake.NewSimpleClientset()
	informersFactory := informers.NewSharedInformerFactory(client, 0)

	npaClient := npaclientfake.NewSimpleClientset()
	npaInformerFactory := npainformers.NewSharedInformerFactory(npaClient, 0)

	controller, err := newController(
		client,
		informersFactory.Networking().V1().NetworkPolicies(),
		informersFactory.Core().V1().Namespaces(),
		informersFactory.Core().V1().Pods(),
		informersFactory.Core().V1().Nodes(),
		npaClient,
		npaInformerFactory.Policy().V1alpha1().AdminNetworkPolicies(),
		npaInformerFactory.Policy().V1alpha1().BaselineAdminNetworkPolicies(),
		config,
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

// execInUserns calls the go test binary again for the same test inside a user namespace where the
// current user is the only one mapped, and it is mapped to root inside the userns. This gives us
// permissions to create network namespaces and iptables rules without running as root on the host.
// This must be only top-level statement in the test function. Do not nest this.
// It will slightly defect the test log output as the test is entered twice
func execInUserns(t *testing.T, f func(t *testing.T)) {
	const subprocessEnvKey = `GO_SUBPROCESS_KEY`
	if testIDString, ok := os.LookupEnv(subprocessEnvKey); ok && testIDString == "1" {
		t.Run(`subprocess`, f)
		return
	}

	cmd := exec.Command(os.Args[0])
	cmd.Args = []string{os.Args[0], "-test.run=" + t.Name() + "$", "-test.v=true"}
	for _, arg := range os.Args {
		if strings.HasPrefix(arg, `-test.testlogfile=`) {
			cmd.Args = append(cmd.Args, arg)
		}
	}
	cmd.Env = append(os.Environ(),
		subprocessEnvKey+"=1",
	)
	// Include sbin in PATH, as some commands are not found otherwise.
	cmd.Env = append(cmd.Env, "PATH=/usr/local/sbin:/usr/sbin::/sbin:"+os.Getenv("PATH"))
	cmd.Stdin = os.Stdin

	// Map ourselves to root inside the userns.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}

	out, err := cmd.CombinedOutput()
	t.Logf("%s", out)
	if err != nil {
		t.Fatal(err)
	}
}

func unpriviledUserns() bool {
	checkUserns.Do(func() {
		cmd := exec.Command("sleep", "1")

		// Map ourselves to root inside the userns.
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Cloneflags:  syscall.CLONE_NEWUSER,
			UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
			GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		}
		if err := cmd.Start(); err != nil {
			// TODO: we can think userns is not supported if the "sleep" binary is not
			// present. This is unlikely, we can do tricks like use /proc/self/exe as
			// the binary to execute and ptrace, so it is never executed, but this seems
			// good enough for the tests.
			return
		}
		defer func() {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}()

		usernsEnabled = true
		return
	})

	return usernsEnabled
}

func TestNetworkPolicies_SyncRules(t *testing.T) {
	if unpriviledUserns() {
		execInUserns(t, testNetworkPolicies_SyncRules)
		return
	}
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges or unprivileged user namespaces")
	}
	testNetworkPolicies_SyncRules(t)
}

func testNetworkPolicies_SyncRules(t *testing.T) {
	tests := []struct {
		name             string
		config           Config
		expectedNftables string
	}{
		{
			name: "default",
			config: Config{
				AdminNetworkPolicy:         false,
				BaselineAdminNetworkPolicy: false,
				NetfilterBug1766Fix:        true,
				QueueID:                    102,
				FailOpen:                   true,
				NFTableName:                "kube-network-policies",
			},
			expectedNftables: `
table inet kube-network-policies {
        set podips-v4 {
                type ipv4_addr
        }

        set podips-v6 {
                type ipv6_addr
        }

        chain postrouting {
                type filter hook postrouting priority srcnat - 5; policy accept;
                udp dport 53 accept
                icmpv6 type nd-router-solicit accept
                icmpv6 type nd-router-advert accept
                icmpv6 type nd-neighbor-solicit accept
                icmpv6 type nd-neighbor-advert accept
                icmpv6 type nd-redirect accept
                meta skuid 0 accept
                ct state established,related accept
                ip saddr @podips-v4 queue flags bypass to 102
                ip daddr @podips-v4 queue flags bypass to 102
                ip6 saddr @podips-v6 queue flags bypass to 102
                ip6 daddr @podips-v6 queue flags bypass to 102
        }

        chain prerouting {
                type filter hook prerouting priority dstnat + 5; policy accept;
                meta l4proto != udp accept
                udp dport != 53 accept
                ip saddr @podips-v4 queue flags bypass to 102
                ip daddr @podips-v4 queue flags bypass to 102
                ip6 saddr @podips-v6 queue flags bypass to 102
                ip6 daddr @podips-v6 queue flags bypass to 102
        }
}
`,
		},
		{
			name: "admin network policy",
			config: Config{
				AdminNetworkPolicy:         true,
				BaselineAdminNetworkPolicy: true,
				NetfilterBug1766Fix:        true,
				QueueID:                    102,
				NFTableName:                "kube-network-policies",
				FailOpen:                   false,
			},
			expectedNftables: `
table inet kube-network-policies {
        chain postrouting {
                type filter hook postrouting priority srcnat - 5; policy accept;
                udp dport 53 accept
                icmpv6 type nd-router-solicit accept
                icmpv6 type nd-router-advert accept
                icmpv6 type nd-neighbor-solicit accept
                icmpv6 type nd-neighbor-advert accept
                icmpv6 type nd-redirect accept
                meta skuid 0 accept
                ct state established,related accept
                queue to 102
        }

        chain prerouting {
                type filter hook prerouting priority dstnat + 5; policy accept;
                meta l4proto != udp accept
                udp dport != 53 accept
                queue to 102
        }
}
`,
		},
		{
			name: "bug disabled",
			config: Config{
				AdminNetworkPolicy:         false,
				BaselineAdminNetworkPolicy: false,
				NetfilterBug1766Fix:        false,
				QueueID:                    102,
				FailOpen:                   true,
				NFTableName:                "kube-network-policies",
			},
			expectedNftables: `
table inet kube-network-policies {
        set podips-v4 {
                type ipv4_addr
        }

        set podips-v6 {
                type ipv6_addr
        }

        chain postrouting {
                type filter hook postrouting priority srcnat - 5; policy accept;
                icmpv6 type nd-router-solicit accept
                icmpv6 type nd-router-advert accept
                icmpv6 type nd-neighbor-solicit accept
                icmpv6 type nd-neighbor-advert accept
                icmpv6 type nd-redirect accept
                meta skuid 0 accept
                ct state established,related accept
                ip saddr @podips-v4 queue flags bypass to 102
                ip daddr @podips-v4 queue flags bypass to 102
                ip6 saddr @podips-v6 queue flags bypass to 102
                ip6 daddr @podips-v6 queue flags bypass to 102
        }
}
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			// Save the current network namespace
			origns, err := netns.Get()
			if err != nil {
				t.Fatal(err)
			}
			defer origns.Close()

			// Create a new network namespace
			newns, err := netns.New()
			if err != nil {
				t.Fatal(err)
			}
			defer newns.Close()

			ma := newTestController(tt.config)

			if err := ma.syncNFTablesRules(context.Background()); err != nil {
				t.Fatalf("SyncRules() error = %v", err)
			}

			cmd := exec.Command("nft", "list", "table", "inet", ma.config.NFTableName)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("nft list table error = %v", err)
			}
			got := string(out)
			if !compareMultilineStringsIgnoreIndentation(got, tt.expectedNftables) {
				t.Errorf("Got:\n%s\nExpected:\n%s\nDiff:\n%s", got, tt.expectedNftables, cmp.Diff(got, tt.expectedNftables))
			}
			ma.cleanNFTablesRules(context.Background())
			cmd = exec.Command("nft", "list", "table", "inet", ma.config.NFTableName)
			out, err = cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("nft list ruleset unexpected success")
			}
			if !strings.Contains(string(out), "No such file or directory") {
				t.Errorf("unexpected error %v %s", err, string(out))
			}
			// Switch back to the original namespace
			netns.Set(origns)
		})
	}
}

func compareMultilineStringsIgnoreIndentation(str1, str2 string) bool {
	// Remove all indentation from both strings
	re := regexp.MustCompile(`(?m)^\s+`)
	str1 = re.ReplaceAllString(str1, "")
	str2 = re.ReplaceAllString(str2, "")

	return str1 == str2
}
