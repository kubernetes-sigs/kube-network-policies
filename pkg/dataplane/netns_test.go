package dataplane

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

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
