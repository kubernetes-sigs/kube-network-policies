package dataplane

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os/exec"
	"sync"
	"syscall"
	"testing"
	"time"

	"sigs.k8s.io/kube-network-policies/pkg/api"
	"sigs.k8s.io/kube-network-policies/pkg/network"
)

// TestController_CloseDeniedConnection verifies that a connection without the
// accept label that the policies deny can still be closed: its data is
// dropped, but the packets that close it have no payload, are not queued and
// reach the peer.
//
// Ref: https://github.com/kubernetes-sigs/kube-network-policies/issues/440
func TestController_CloseDeniedConnection(t *testing.T) {
	if !unpriviledUserns() {
		t.Skip("Test requires unprivileged user namespaces")
	}
	execInUserns(t, testController_CloseDeniedConnection, syscall.CLONE_NEWNET)
}

func testController_CloseDeniedConnection(t *testing.T) {
	if out, err := exec.Command("ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
		t.Fatalf("failed to bring lo up: %v: %s", err, out)
	}
	// Track the connections before the agent starts, as kube-proxy or the CNI
	// do on a node.
	if out, err := exec.Command("nft", "add table inet pre_existing; add chain inet pre_existing c { type filter hook output priority 0; ct state new counter; }").CombinedOutput(); err != nil {
		t.Fatalf("failed to enable conntrack in netns: %v: %s", err, out)
	}

	// Connections opened before the agent starts have no accept label, so all
	// their packets go through the queue rules. One connection to send data
	// and one that stays idle, for each IP family.
	type conns struct {
		clientData, serverData net.Conn
		clientIdle, serverIdle net.Conn
	}
	families := map[string]*conns{}
	for family, address := range map[string]string{"IPv4": "127.0.0.1:12345", "IPv6": "[::1]:12345"} {
		ln := listenTCP(t, address)
		dial := func() (client, server net.Conn) {
			client, err := net.DialTimeout("tcp", address, 5*time.Second)
			if err != nil {
				t.Fatalf("failed to dial %s: %v", address, err)
			}
			t.Cleanup(func() { client.Close() })
			return client, acceptTCP(t, ln)
		}
		c := &conns{}
		c.clientData, c.serverData = dial()
		c.clientIdle, c.serverIdle = dial()
		families[family] = c
	}

	// Deny everything and count the packets evaluated for each connection,
	// they are evaluated in the original direction of the connection.
	var mu sync.Mutex
	evaluated := map[int]int{}
	evaluations := func(client net.Conn) int {
		mu.Lock()
		defer mu.Unlock()
		return evaluated[client.LocalAddr().(*net.TCPAddr).Port]
	}
	evaluator := &mockPolicyEvaluator{
		name:    "deny-all-evaluator",
		ips:     []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")},
		isReady: true,
		evaluateEgress: func(_ context.Context, p *network.Packet, _, _ *api.PodInfo) (api.Verdict, error) {
			mu.Lock()
			evaluated[p.SrcPort]++
			mu.Unlock()
			return api.VerdictDeny, nil
		},
	}

	config := Config{
		QueueID:         205,
		NFTableName:     "test-close-denied",
		skipSkuidBypass: true,
	}
	if err := config.Defaults(); err != nil {
		t.Fatalf("Defaults() error = %v", err)
	}
	controller := newTestController(config, []api.PolicyEvaluator{evaluator})
	go func() {
		_ = controller.Run(t.Context())
	}()
	waitForController(t, "127.0.0.1:54321")

	for family, c := range families {
		t.Run(family, func(t *testing.T) {
			buf := make([]byte, 16)
			timesOut := func(conn net.Conn) bool {
				_ = conn.SetReadDeadline(time.Now().Add(time.Second))
				_, err := conn.Read(buf)
				var ne net.Error
				return errors.As(err, &ne) && ne.Timeout()
			}

			// The data is evaluated and denied. It is also denied when the FIN
			// carries it, as TCP does when it sends again the data of a closed
			// connection.
			if _, err := c.clientData.Write([]byte("data")); err != nil {
				t.Fatalf("clientData write failed: %v", err)
			}
			if err := c.clientData.Close(); err != nil {
				t.Fatalf("clientData close failed: %v", err)
			}
			if !timesOut(c.serverData) {
				t.Fatalf("the data of the denied connection reached the server")
			}
			if evaluations(c.clientData) == 0 {
				t.Fatalf("the data of the denied connection was not evaluated")
			}

			// The close of a connection with no data in flight reaches the
			// server, that closes its side.
			if err := c.clientIdle.Close(); err != nil {
				t.Fatalf("clientIdle close failed: %v", err)
			}
			_ = c.serverIdle.SetReadDeadline(time.Now().Add(2 * time.Second))
			if _, err := c.serverIdle.Read(buf); !errors.Is(err, io.EOF) {
				t.Fatalf("serverIdle read after the client closed = %v, want EOF: the FIN did not reach the server", err)
			}
			if err := c.serverIdle.Close(); err != nil {
				t.Fatalf("serverIdle close failed: %v", err)
			}
			// None of the FIN and ACK of the close went to the queue.
			time.Sleep(200 * time.Millisecond)
			if n := evaluations(c.clientIdle); n != 0 {
				t.Errorf("%d packets of the close were evaluated, want 0", n)
			}
		})
	}
}
