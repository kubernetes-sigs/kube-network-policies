package dataplane

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/vishvananda/netns"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"sigs.k8s.io/kube-network-policies/pkg/api"
	"sigs.k8s.io/kube-network-policies/pkg/network"
	"sigs.k8s.io/kube-network-policies/pkg/networkpolicy"
	"sigs.k8s.io/kube-network-policies/pkg/podinfo"
	"sigs.k8s.io/kube-network-policies/pkg/runner"
)

var (
	usernsEnabled bool
	checkUserns   sync.Once
)

// mockPolicyEvaluator is a mock implementation of the PolicyEvaluator interface for testing.
type mockPolicyEvaluator struct {
	name      string
	ips       []netip.Addr
	divertAll bool
	isReady   bool
	sync      api.SyncFunc
}

func (m *mockPolicyEvaluator) Name() string { return m.name }
func (m *mockPolicyEvaluator) EvaluateIngress(context.Context, *network.Packet, *api.PodInfo, *api.PodInfo) (api.Verdict, error) {
	return api.VerdictNext, nil
}
func (m *mockPolicyEvaluator) EvaluateEgress(context.Context, *network.Packet, *api.PodInfo, *api.PodInfo) (api.Verdict, error) {
	return api.VerdictNext, nil
}
func (m *mockPolicyEvaluator) SetDataplaneSyncCallback(syncFn api.SyncFunc) {
	m.sync = syncFn
}
func (m *mockPolicyEvaluator) Ready() bool { return m.isReady }
func (m *mockPolicyEvaluator) ManagedIPs(context.Context) ([]netip.Addr, bool, error) {
	return m.ips, m.divertAll, nil
}

// newTestController creates a controller instance for testing with mock evaluators.
func newTestController(config Config, evaluators []api.PolicyEvaluator) *Controller {
	client := fake.NewSimpleClientset()
	informersFactory := informers.NewSharedInformerFactory(client, 0)
	podInformer := informersFactory.Core().V1().Pods()
	nsInfomer := informersFactory.Core().V1().Namespaces()

	// PodInfoProvider is needed by the engine, but our mock evaluators don't use it.
	podInfoProvider := podinfo.NewInformerProvider(podInformer, nsInfomer, nil, nil)
	engine := networkpolicy.NewPolicyEngine(podInfoProvider, evaluators)

	// We can't use the real NewController because it creates a real BoundedFrequencyRunner
	// which we can't easily control in a test. We create the controller directly and
	// set a mock runner.
	controller := &Controller{
		config:       config,
		policyEngine: engine,
	}
	// The sync function for the mock runner just calls the sync function directly.
	controller.syncRunner = runner.NewBoundedFrequencyRunner(
		"test-runner",
		func() error { return controller.syncNFTablesRules(context.Background()) },
		1*time.Millisecond, 1*time.Millisecond, 10*time.Second)
	engine.SetDataplaneSyncCallbacks(controller.syncRunner.Run)

	return controller
}

func TestConfig_Defaults(t *testing.T) {
	tests := []struct {
		name     string
		config   Config
		expected Config
	}{
		{
			name:   "empty",
			config: Config{},
			expected: Config{
				FailOpen:            false,
				QueueID:             100,
				NetfilterBug1766Fix: false,
				NFTableName:         "kube-network-policies",
				CTLabelAccept:       100,
			},
		}, {
			name: "queue id",
			config: Config{
				QueueID: 99,
			},
			expected: Config{
				FailOpen:            false,
				QueueID:             99,
				NetfilterBug1766Fix: false,
				NFTableName:         "kube-network-policies",
				CTLabelAccept:       100,
			},
		}, {
			name: "table name",
			config: Config{
				QueueID:     99,
				NFTableName: "kindnet-network-policies",
			},
			expected: Config{
				FailOpen:            false,
				QueueID:             99,
				NetfilterBug1766Fix: false,
				NFTableName:         "kindnet-network-policies",
				CTLabelAccept:       100,
			},
		}, {
			name: "ct label",
			config: Config{
				QueueID:       99,
				NFTableName:   "kindnet-network-policies",
				CTLabelAccept: 101,
			},
			expected: Config{
				FailOpen:            false,
				QueueID:             99,
				NetfilterBug1766Fix: false,
				NFTableName:         "kindnet-network-policies",
				CTLabelAccept:       101,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := tt.config
			if err := c.Defaults(); err != nil {
				t.Errorf("Config.Defaults() error = %v", err)
			}

			if diff := cmp.Diff(tt.expected, c, cmpopts.EquateComparable(Config{})); diff != "" {
				t.Errorf("Config.Defaults() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// execInUserns calls the go test binary again for the same test inside a user namespace where the
// current user is the only one mapped, and it is mapped to root inside the userns. This gives us
// permissions to create network namespaces and iptables rules without running as root on the host.
// This must be only top-level statement in the test function. Do not nest this.
// It will slightly defect the test log output as the test is entered twice
//
// extraCloneflags can be used to request additional namespace types, e.g.
// syscall.CLONE_NEWNET to also create a network namespace in the same clone.
func execInUserns(t *testing.T, f func(t *testing.T), extraCloneflags ...uintptr) {
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

	cloneflags := uintptr(syscall.CLONE_NEWUSER)
	for _, f := range extraCloneflags {
		cloneflags |= f
	}
	// Map ourselves to root inside the userns.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  cloneflags,
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
		evaluators       []api.PolicyEvaluator
		expectedNftables string
	}{
		{
			name: "default with pod IPs",
			config: Config{
				NetfilterBug1766Fix: true,
				QueueID:             102,
				FailOpen:            true,
				NFTableName:         "kube-network-policies",
			},
			evaluators: []api.PolicyEvaluator{
				&mockPolicyEvaluator{
					name: "test-evaluator",
					ips: []netip.Addr{
						netip.MustParseAddr("10.0.0.1"),
						netip.MustParseAddr("fd00::1"),
					},
					isReady: true,
				},
			},
			expectedNftables: `
table inet kube-network-policies {
	set podips-v4 {
		type ipv4_addr
		elements = { 10.0.0.1 }
	}

	set podips-v6 {
		type ipv6_addr
		elements = { fd00::1 }
	}

	chain postrouting {
		type filter hook postrouting priority srcnat - 5; policy accept;
		udp dport 53 accept
		icmpv6 type nd-router-solicit accept
		icmpv6 type nd-router-advert accept
		icmpv6 type nd-neighbor-solicit accept
		icmpv6 type nd-neighbor-advert accept
		icmpv6 type nd-redirect accept
		meta skuid 0 counter packets 0 bytes 0 accept
		ct label 28 ct state established,related counter packets 0 bytes 0 accept
		ip saddr @podips-v4 queue flags bypass to 102
		ip daddr @podips-v4 queue flags bypass to 102
		ip6 saddr @podips-v6 queue flags bypass to 102
		ip6 daddr @podips-v6 queue flags bypass to 102
		ct label set 28
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
			name: "divert all traffic",
			config: Config{
				NetfilterBug1766Fix: true,
				QueueID:             102,
				NFTableName:         "kube-network-policies",
				FailOpen:            false,
			},
			evaluators: []api.PolicyEvaluator{
				&mockPolicyEvaluator{
					name:      "divert-all-evaluator",
					divertAll: true,
					isReady:   true,
				},
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
		meta skuid 0 counter packets 0 bytes 0 accept
		ct label 28 ct state established,related counter packets 0 bytes 0 accept
		queue to 102
		ct label set 28
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
			name: "mixed evaluators where one requests divert all",
			config: Config{
				QueueID:     102,
				NFTableName: "kube-network-policies",
			},
			evaluators: []api.PolicyEvaluator{
				&mockPolicyEvaluator{
					name:    "ip-evaluator",
					ips:     []netip.Addr{netip.MustParseAddr("10.0.0.1")},
					isReady: true,
				},
				&mockPolicyEvaluator{
					name:      "divert-all-evaluator",
					divertAll: true,
					isReady:   true,
				},
			},
			expectedNftables: `
table inet kube-network-policies {
	chain postrouting {
		type filter hook postrouting priority srcnat - 5; policy accept;
		icmpv6 type nd-router-solicit accept
		icmpv6 type nd-router-advert accept
		icmpv6 type nd-neighbor-solicit accept
		icmpv6 type nd-neighbor-advert accept
		icmpv6 type nd-redirect accept
		meta skuid 0 counter packets 0 bytes 0 accept
		ct label 28 ct state established,related counter packets 0 bytes 0 accept
		queue to 102
		ct label set 28
	}
}
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			origns, err := netns.Get()
			if err != nil {
				t.Fatal(err)
			}
			defer origns.Close()

			newns, err := netns.New()
			if err != nil {
				t.Fatal(err)
			}
			defer newns.Close()

			if err := tt.config.Defaults(); err != nil {
				t.Fatalf("Defaults() error = %v", err)
			}

			ma := newTestController(tt.config, tt.evaluators)
			if !ma.policyEngine.Ready() {
				t.Fatalf("Policy engine is not ready")
			}

			if err := ma.syncNFTablesRules(context.Background()); err != nil {
				t.Fatalf("SyncRules() error = %v", err)
			}

			cmd := exec.Command("nft", "list", "table", "inet", ma.config.NFTableName)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("nft list table error = %v, output: %s", err, string(out))
			}
			got := string(out)
			if !compareMultilineStringsIgnoreIndentation(got, tt.expectedNftables) {
				t.Errorf("nftables rules mismatch (-got +want):\n%s", cmp.Diff(strings.TrimSpace(tt.expectedNftables), strings.TrimSpace(got)))
			}
			ma.cleanNFTablesRules(context.Background())
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

// TestController_Run exercises the full dataplane path: nftables rule sync,
// nfqueue packet interception, verdict processing, and packet delivery.
// It verifies that Controller.Run correctly receives and processes packets
// through the nfqueue netlink socket.
func TestController_Run(t *testing.T) {
	if !unpriviledUserns() {
		t.Skip("Test requires unprivileged user namespaces")
	}
	execInUserns(t, testController_Run, syscall.CLONE_NEWNET)
}

func testController_Run(t *testing.T) {
	// lo starts DOWN in a new netns (created via CLONE_NEWNET).
	if out, err := exec.Command("ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
		t.Fatalf("failed to bring lo up: %v: %s", err, out)
	}

	evaluators := []api.PolicyEvaluator{
		&mockPolicyEvaluator{
			name:      "accept-all",
			divertAll: true,
			isReady:   true,
		},
	}

	config := Config{
		QueueID:         200,
		FailOpen:        false,
		NFTableName:     "test-controller-run",
		skipSkuidBypass: true,
	}

	controller := newTestController(config, evaluators)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- controller.Run(ctx)
	}()

	// Give the controller time to set up nftables rules and open nfqueue.
	time.Sleep(500 * time.Millisecond)

	// Verify the controller is still running
	select {
	case err := <-errCh:
		t.Fatalf("controller.Run exited prematurely: %v", err)
	default:
	}

	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()
	listener.SetDeadline(time.Now().Add(5 * time.Second))

	// Send a UDP packet. With skipSkuidBypass the "meta skuid 0 accept" rule
	// is absent, so all traffic enters nfqueue.
	conn, err := net.Dial("udp", listener.LocalAddr().String())
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	fmt.Fprint(conn, "controller-run-test")
	conn.Close()

	// If nfqueue processing is broken, the packet stays queued and times out.
	buf := make([]byte, 256)
	n, _, err := listener.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("failed to receive UDP packet (nfqueue processing broken): %v", err)
	}
	if got := string(buf[:n]); got != "controller-run-test" {
		t.Errorf("received %q, want %q", got, "controller-run-test")
	}

	cancel()
	if err := <-errCh; err != nil {
		t.Logf("controller.Run returned: %v", err)
	}
}
