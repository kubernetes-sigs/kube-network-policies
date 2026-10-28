package dataplane

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"sigs.k8s.io/kube-network-policies/pkg/api"
	"sigs.k8s.io/kube-network-policies/pkg/network"
	"sigs.k8s.io/kube-network-policies/pkg/runner"
)

// TestController_RejectRepliesNotQueued verifies that the packets the kernel
// generates to answer a rejected packet (the ICMP port unreachable of "reject"
// and the TCP RST of "reject with tcp reset", as used by kube-proxy for
// Services without endpoints) reach the client while the agent is running.
//
// Those packets carry the conntrack entry of the rejected packet, which is
// never confirmed: the rejected packet did not get past the hook that rejected
// it. They have no socket, so "meta skuid 0" does not match, and they have no
// label, so they used to fall through to the queue rule. nfqueue refuses to
// queue a packet whose unconfirmed conntrack entry is shared with another
// packet (nf_ct_drop_unconfirmed) and the kernel frees it silently; the bypass
// flag does not apply because the queue is bound. The client then retries
// until it times out instead of failing at once.
//
// Ref: https://github.com/kubernetes-sigs/kube-network-policies/issues/425
func TestController_RejectRepliesNotQueued(t *testing.T) {
	if !unpriviledUserns() {
		t.Skip("Test requires unprivileged user namespaces")
	}
	execInUserns(t, testController_RejectRepliesNotQueued, syscall.CLONE_NEWNET)
}

func testController_RejectRepliesNotQueued(t *testing.T) {
	const (
		localIP   = "10.0.0.1"
		remoteIP  = "10.0.0.2"
		probePort = 54321
	)

	if out, err := exec.Command("ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
		t.Fatalf("failed to bring lo up: %v: %s", err, out)
	}

	remoteNS := newNetns(t)
	addVethPair(t, remoteNS, localIP+"/24", remoteIP+"/24")

	// Reject rules like the ones kube-proxy installs for Services without
	// endpoints, in the input hook for clients on other nodes and in the
	// output hook for clients on this node. Both run before the agent's
	// chains, so the rejected SYN never reaches them.
	cases := []struct {
		name string
		hook string
		port int
		with string
	}{
		{name: "input icmp port unreachable", hook: "input", port: 81, with: "reject"},
		{name: "input tcp reset", hook: "input", port: 82, with: "reject with tcp reset"},
		{name: "output icmp port unreachable", hook: "output", port: 83, with: "reject"},
		{name: "output tcp reset", hook: "output", port: 84, with: "reject with tcp reset"},
	}
	rules := "add table inet reject_test;" +
		" add chain inet reject_test input { type filter hook input priority 0; };" +
		" add chain inet reject_test output { type filter hook output priority 0; };"
	for _, tc := range cases {
		rules += fmt.Sprintf(" add rule inet reject_test %s tcp dport %d counter %s;", tc.hook, tc.port, tc.with)
	}
	if out, err := exec.Command("nft", rules).CombinedOutput(); err != nil {
		t.Fatalf("failed to add the reject rules: %v: %s", err, out)
	}

	// dial connects to the rejected port from the side the hook rejects.
	dial := func(t *testing.T, hook string, port int) error {
		t.Helper()
		var err error
		switch hook {
		case "input":
			inNetns(t, remoteNS, func() error {
				err = dialRefused(net.JoinHostPort(localIP, strconv.Itoa(port)))
				return nil
			})
		case "output":
			err = dialRefused(net.JoinHostPort(remoteIP, strconv.Itoa(port)))
		default:
			t.Fatalf("unknown hook %q", hook)
		}
		return err
	}

	// Without the agent every reject is answered at once.
	for _, tc := range cases {
		if err := dial(t, tc.hook, tc.port); err != nil {
			t.Fatalf("before the agent starts, %s: %v", tc.name, err)
		}
	}

	var (
		mu     sync.Mutex
		probes int
	)
	evaluator := &mockPolicyEvaluator{
		name:      "recording-evaluator",
		divertAll: true,
		isReady:   true,
		evaluateEgress: func(_ context.Context, p *network.Packet, _, _ *api.PodInfo) (api.Verdict, error) {
			mu.Lock()
			defer mu.Unlock()
			if p.DstPort == probePort {
				probes++
				return api.VerdictDeny, nil
			}
			return api.VerdictAccept, nil
		},
	}

	config := Config{
		QueueID:     205,
		FailOpen:    true,
		StrictMode:  true,
		NFTableName: "test-reject",
	}
	if err := config.Defaults(); err != nil {
		t.Fatalf("Defaults() error = %v", err)
	}
	controller := newTestController(config, []api.PolicyEvaluator{evaluator})
	controller.connRunner = runner.NewBoundedFrequencyRunner(
		"test-conn-runner",
		func() error { return nil },
		1*time.Millisecond, 1*time.Millisecond, 10*time.Second)
	go func() {
		_ = controller.Run(t.Context())
	}()

	// The agent is ready once a SYN from the remote node to the denied port is
	// evaluated: that proves the rules are installed and the queue is served.
	probeAddr := net.JoinHostPort(localIP, strconv.Itoa(probePort))
	for deadline := time.Now().Add(10 * time.Second); ; {
		inNetns(t, remoteNS, func() error {
			conn, err := net.DialTimeout("tcp", probeAddr, 100*time.Millisecond)
			if err == nil {
				conn.Close()
			}
			return nil
		})
		mu.Lock()
		ready := probes > 0
		mu.Unlock()
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("controller is not ready: no packet reached the evaluator")
		}
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := dial(t, tc.hook, tc.port); err != nil {
				t.Error(err)
			}
		})
	}
}

// dialRefused connects to address and returns nil if the connection is
// refused at once, as it must be when a reject rule answers the SYN.
func dialRefused(address string) error {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err == nil {
		conn.Close()
		return fmt.Errorf("connection to %s succeeded, want connection refused", address)
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		return fmt.Errorf("connection to %s failed after %v with %v, want connection refused", address, time.Since(start).Round(time.Millisecond), err)
	}
	return nil
}
