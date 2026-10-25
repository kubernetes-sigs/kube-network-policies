package dataplane

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"sigs.k8s.io/kube-network-policies/pkg/api"
	"sigs.k8s.io/kube-network-policies/pkg/network"
	"sigs.k8s.io/kube-network-policies/pkg/runner"
)

// TestController_PreExistingNodeConnectionsNotQueued verifies that connections
// that were established before the agent started, and that do not involve
// pods (kubelet, kube-proxy and the control plane components talking to the
// API server, the API server answering them, ...), never reach the nfqueue.
//
// Conntrack entries created before the agent loads its ruleset can never get
// the accept label: the kernel only allocates the labels extension for entries
// created while "ct label" rules exist (net->ct.labels_used > 0), and the
// extension cannot be added to a confirmed entry. "ct label set" and the label
// sent with the nfqueue verdict are silently ignored for them. So the only
// thing keeping that traffic out of the queue are the rules that do not depend
// on the label. If those are weakened, every packet of every pre-existing node
// connection goes to userspace for as long as the connection lives, which
// saturates the queue on real nodes.
//
// A second network namespace connected with a veth pair plays the remote node,
// so the input chain is exercised with a non loopback interface.
func TestController_PreExistingNodeConnectionsNotQueued(t *testing.T) {
	if !unpriviledUserns() {
		t.Skip("Test requires unprivileged user namespaces")
	}
	execInUserns(t, testController_PreExistingNodeConnectionsNotQueued, syscall.CLONE_NEWNET)
}

func testController_PreExistingNodeConnectionsNotQueued(t *testing.T) {
	const (
		localIP   = "10.0.0.1"
		remoteIP  = "10.0.0.2"
		probePort = 54321
	)

	if out, err := exec.Command("ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
		t.Fatalf("failed to bring lo up: %v: %s", err, out)
	}
	// Conntrack must be active before the connections are created, as on a node
	// where kube-proxy or the CNI already use it, so the entries exist without
	// the labels extension when the agent starts.
	if out, err := exec.Command("nft", "add table inet pre_existing; add chain inet pre_existing c { type filter hook output priority 0; ct state new counter; }").CombinedOutput(); err != nil {
		t.Fatalf("failed to enable conntrack in netns: %v: %s", err, out)
	}

	remoteNS := newNetns(t)
	addVethPair(t, remoteNS, localIP+"/24", remoteIP+"/24")

	// Root owned servers on both nodes, e.g. the API server on the control
	// plane and the kubelet on a worker.
	localLn := listenTCP(t, net.JoinHostPort(localIP, "0"))
	var remoteLn net.Listener
	inNetns(t, remoteNS, func() error {
		var err error
		remoteLn, err = net.Listen("tcp", net.JoinHostPort(remoteIP, "0"))
		return err
	})
	if remoteLn != nil {
		t.Cleanup(func() { remoteLn.Close() })
	}

	// Pre-existing connections in both directions:
	//  - inbound:  remote node -> local server (packets enter through input,
	//              the replies leave through postrouting).
	//  - outbound: local client -> remote server (packets leave through
	//              postrouting, the replies enter through input).
	var inboundClient net.Conn
	inNetns(t, remoteNS, func() error {
		var err error
		inboundClient, err = net.DialTimeout("tcp", localLn.Addr().String(), 5*time.Second)
		return err
	})
	t.Cleanup(func() { inboundClient.Close() })
	inboundServer := acceptTCP(t, localLn)

	outboundClient, err := net.DialTimeout("tcp", remoteLn.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("failed to dial the remote server: %v", err)
	}
	t.Cleanup(func() { outboundClient.Close() })
	outboundServer := acceptTCP(t, remoteLn)

	// Traffic in both directions so conntrack sees the connections established.
	roundTrip(t, inboundClient, inboundServer)
	roundTrip(t, outboundClient, outboundServer)

	// Record every packet that reaches the queue. Connections to probePort are
	// denied so the test can tell when the queue is bound and served.
	var (
		mu     sync.Mutex
		queued []queuedPacket
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
			queued = append(queued, queuedPacket{
				src:   net.JoinHostPort(p.SrcIP.String(), strconv.Itoa(p.SrcPort)),
				dst:   net.JoinHostPort(p.DstIP.String(), strconv.Itoa(p.DstPort)),
				proto: string(p.Proto),
			})
			return api.VerdictAccept, nil
		},
	}

	config := Config{
		QueueID:     204,
		FailOpen:    false,
		StrictMode:  true,
		NFTableName: "test-node-conns",
		// Keep the default skipSkuidBypass: false, the node traffic rules are
		// what this test is about.
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

	for i := 0; i < 5; i++ {
		roundTrip(t, inboundClient, inboundServer)
		roundTrip(t, outboundClient, outboundServer)
	}
	// Let any in-flight ACK traverse the hooks before checking.
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	seen := append([]queuedPacket(nil), queued...)
	mu.Unlock()
	for _, conn := range []struct {
		name string
		conn net.Conn
	}{
		{"inbound (remote node -> local server)", inboundClient},
		{"outbound (local client -> remote server)", outboundClient},
	} {
		if pkts := packetsOfConn(seen, conn.conn); len(pkts) > 0 {
			t.Errorf("%d packets of the pre-existing %s connection were sent to the queue, want 0:\n%s",
				len(pkts), conn.name, formatPackets(pkts))
		}
	}
	if t.Failed() {
		t.FailNow()
	}

	// Sanity check: a connection created now still goes through the queue,
	// otherwise the test could pass because nothing is being evaluated.
	var newClient net.Conn
	inNetns(t, remoteNS, func() error {
		var err error
		newClient, err = net.DialTimeout("tcp", localLn.Addr().String(), 5*time.Second)
		return err
	})
	t.Cleanup(func() { newClient.Close() })
	newServer := acceptTCP(t, localLn)
	roundTrip(t, newClient, newServer)

	mu.Lock()
	seen = append([]queuedPacket(nil), queued...)
	mu.Unlock()
	if pkts := packetsOfConn(seen, newClient); len(pkts) == 0 {
		t.Fatalf("no packet of a new connection %s -> %s reached the queue, the agent is not evaluating traffic",
			newClient.LocalAddr(), newClient.RemoteAddr())
	}
}

// queuedPacket identifies a packet that reached the nfqueue.
type queuedPacket struct {
	src, dst, proto string
}

// packetsOfConn returns the packets that belong to conn, in either direction.
func packetsOfConn(pkts []queuedPacket, conn net.Conn) []queuedPacket {
	local, remote := conn.LocalAddr().String(), conn.RemoteAddr().String()
	var result []queuedPacket
	for _, p := range pkts {
		if (p.src == local && p.dst == remote) || (p.src == remote && p.dst == local) {
			result = append(result, p)
		}
	}
	return result
}

func formatPackets(pkts []queuedPacket) string {
	var b []byte
	for _, p := range pkts {
		b = fmt.Appendf(b, "\t%s -> %s %s\n", p.src, p.dst, p.proto)
	}
	return string(b)
}

// newNetns creates a new network namespace and returns a handle to it. The
// namespace is only entered by the throwaway thread that creates it.
func newNetns(t *testing.T) netns.NsHandle {
	t.Helper()
	type result struct {
		ns  netns.NsHandle
		err error
	}
	ch := make(chan result, 1)
	go func() {
		// netns.New switches the calling thread to the new namespace. The
		// goroutine stays locked to its thread until it exits, so the runtime
		// discards the thread instead of reusing it for other goroutines.
		runtime.LockOSThread()
		ns, err := netns.New()
		ch <- result{ns: ns, err: err}
	}()
	r := <-ch
	if r.err != nil {
		t.Fatalf("failed to create network namespace: %v", r.err)
	}
	t.Cleanup(func() { r.ns.Close() })
	return r.ns
}

// inNetns runs f on a throwaway thread switched to ns. Sockets created by f
// belong to ns and can be used from any goroutine afterwards.
func inNetns(t *testing.T, ns netns.NsHandle, f func() error) {
	t.Helper()
	ch := make(chan error, 1)
	go func() {
		runtime.LockOSThread() // never unlocked on purpose, see newNetns
		if err := netns.Set(ns); err != nil {
			ch <- fmt.Errorf("failed to enter network namespace: %w", err)
			return
		}
		ch <- f()
	}()
	if err := <-ch; err != nil {
		t.Fatal(err)
	}
}

// addVethPair connects the current network namespace with ns through a veth
// pair, with localAddr on this end and remoteAddr on the other end.
func addVethPair(t *testing.T, ns netns.NsHandle, localAddr, remoteAddr string) {
	t.Helper()
	// Keep IPv6 autoconfiguration (MLD reports, DAD) out of the picture, the
	// test only looks at the TCP connections it creates.
	if err := disableIPv6(); err != nil {
		t.Fatal(err)
	}
	inNetns(t, ns, disableIPv6)

	veth := &netlink.Veth{
		LinkAttrs:     netlink.LinkAttrs{Name: "veth0"},
		PeerName:      "veth1",
		PeerNamespace: netlink.NsFd(int(ns)),
	}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatalf("failed to create veth pair: %v", err)
	}
	addr, err := netlink.ParseAddr(localAddr)
	if err != nil {
		t.Fatalf("failed to parse %q: %v", localAddr, err)
	}
	if err := netlink.AddrAdd(veth, addr); err != nil {
		t.Fatalf("failed to add %s to veth0: %v", localAddr, err)
	}
	if err := netlink.LinkSetUp(veth); err != nil {
		t.Fatalf("failed to bring veth0 up: %v", err)
	}

	remote, err := netlink.NewHandleAt(ns)
	if err != nil {
		t.Fatalf("failed to open netlink handle in the remote namespace: %v", err)
	}
	defer remote.Close()
	peer, err := remote.LinkByName("veth1")
	if err != nil {
		t.Fatalf("failed to find veth1 in the remote namespace: %v", err)
	}
	peerAddr, err := netlink.ParseAddr(remoteAddr)
	if err != nil {
		t.Fatalf("failed to parse %q: %v", remoteAddr, err)
	}
	if err := remote.AddrAdd(peer, peerAddr); err != nil {
		t.Fatalf("failed to add %s to veth1: %v", remoteAddr, err)
	}
	if err := remote.LinkSetUp(peer); err != nil {
		t.Fatalf("failed to bring veth1 up: %v", err)
	}
}

// disableIPv6 disables IPv6 on all current and future interfaces of the
// network namespace of the calling thread.
func disableIPv6() error {
	for _, name := range []string{"all", "default"} {
		path := "/proc/sys/net/ipv6/conf/" + name + "/disable_ipv6"
		if err := os.WriteFile(path, []byte("1"), 0o644); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("failed to write %s: %w", path, err)
		}
	}
	return nil
}

func listenTCP(t *testing.T, address string) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatalf("failed to listen on %s: %v", address, err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

// acceptTCP accepts one connection from ln and closes it when the test ends.
func acceptTCP(t *testing.T, ln net.Listener) net.Conn {
	t.Helper()
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := ln.Accept()
		ch <- result{conn: conn, err: err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("failed to accept on %s: %v", ln.Addr(), r.err)
		}
		t.Cleanup(func() { r.conn.Close() })
		return r.conn
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for a connection on %s", ln.Addr())
		return nil
	}
}

// roundTrip sends a request from client to server and a reply back.
func roundTrip(t *testing.T, client, server net.Conn) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for _, c := range []net.Conn{client, server} {
		if err := c.SetDeadline(deadline); err != nil {
			t.Fatal(err)
		}
	}
	buf := make([]byte, 16)
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("client %s write failed: %v", client.LocalAddr(), err)
	}
	if n, err := server.Read(buf); err != nil || string(buf[:n]) != "ping" {
		t.Fatalf("server %s read = %q, %v; want %q", server.LocalAddr(), buf[:n], err, "ping")
	}
	if _, err := server.Write([]byte("pong")); err != nil {
		t.Fatalf("server %s write failed: %v", server.LocalAddr(), err)
	}
	if n, err := client.Read(buf); err != nil || string(buf[:n]) != "pong" {
		t.Fatalf("client %s read = %q, %v; want %q", client.LocalAddr(), buf[:n], err, "pong")
	}
}
