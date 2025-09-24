package dataplane

import (
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"

	vishnetlink "github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	"k8s.io/component-base/logs"
	"sigs.k8s.io/kube-network-policies/pkg/dataplane/conntrack"
	"sigs.k8s.io/kube-network-policies/pkg/network"
	"sigs.k8s.io/kube-network-policies/pkg/socket"
)

func TestSeekAndDestroySocket(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges or unprivileged user namespaces")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	origns, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer origns.Close()

	rndString := make([]byte, 4)
	_, err = rand.Read(rndString)
	if err != nil {
		t.Errorf("fail to generate random name: %v", err)
	}
	nsName := fmt.Sprintf("ns%x", rndString)
	newns, err := netns.NewNamed(nsName)
	if err != nil {
		t.Fatalf("Failed to create network namespace: %v", err)
	}
	defer netns.DeleteNamed(nsName)
	defer newns.Close()

	// Return to original namespace
	if err := netns.Set(origns); err != nil {
		t.Fatal(err)
	}

	// Create a veth pair
	veth := &vishnetlink.Veth{
		LinkAttrs: vishnetlink.LinkAttrs{
			Name: "veth-root",
		},
		PeerName: "veth-ns",
	}

	_ = vishnetlink.LinkDel(veth) // Clean up if it already exists

	if err := vishnetlink.LinkAdd(veth); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := vishnetlink.LinkDel(veth); err != nil {
			t.Logf("failed to delete veth pair: %v", err)
		}
	}()
	t.Logf("created veth pair: %s <-> %s", veth.LinkAttrs.Name, veth.PeerName)

	// Move peer to the new namespace
	peer, err := vishnetlink.LinkByName("veth-ns")
	if err != nil {
		t.Fatal(err)
	}
	if err := vishnetlink.LinkSetNsFd(peer, int(newns)); err != nil {
		t.Fatal(err)
	}
	t.Logf("moved %s to new namespace", peer.Attrs().Name)

	// Configure root side
	rootLink, err := vishnetlink.LinkByName("veth-root")
	if err != nil {
		t.Fatal(err)
	}
	addrRoot, err := vishnetlink.ParseAddr("10.254.55.1/29")
	if err != nil {
		t.Fatal(err)
	}
	if err := vishnetlink.AddrAdd(rootLink, addrRoot); err != nil {
		t.Fatal(err)
	}
	if err := vishnetlink.LinkSetUp(rootLink); err != nil {
		t.Fatal(err)
	}

	// Switch to new namespace to configure the other side
	if err := netns.Set(newns); err != nil {
		t.Fatal(err)
	}

	nsLink, err := vishnetlink.LinkByName("veth-ns")
	if err != nil {
		t.Fatal(err)
	}
	addrNs, err := vishnetlink.ParseAddr("10.254.55.2/29")
	if err != nil {
		t.Fatal(err)
	}
	if err := vishnetlink.AddrAdd(nsLink, addrNs); err != nil {
		t.Fatal(err)
	}
	if err := vishnetlink.LinkSetUp(nsLink); err != nil {
		t.Fatal(err)
	}
	t.Logf("configured %s with %s", nsLink.Attrs().Name, addrNs.String())

	// Return to original namespace
	if err := netns.Set(origns); err != nil {
		t.Fatal(err)
	}

	err = vishnetlink.RouteAdd(&vishnetlink.Route{
		LinkIndex: rootLink.Attrs().Index,
		Scope:     vishnetlink.SCOPE_HOST,
		Dst:       &net.IPNet{IP: net.IPv4(10, 254, 55, 2), Mask: net.CIDRMask(32, 32)},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Start TCP echo server in the new namespace.
	tcpListener, err := ListenInNamespace("tcp", "10.254.55.2:8080", int(newns))
	if err != nil {
		t.Fatalf("ListenInNamespace (TCP) failed: %v", err)
	}
	defer tcpListener.Close()

	go func() {
		for {
			conn, err := tcpListener.Accept()
			if err != nil {
				// When the listener is closed, Accept will return an error.
				return
			}
			go func(c net.Conn) { // Simple echo handler
				// hold the connection open
				for {
					buf := make([]byte, 1024)
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					c.Write(buf[:n])
				}
			}(conn)
		}
	}()
	t.Log("TCP server started in namespace via helper")

	// Allow some time for servers to start
	time.Sleep(100 * time.Millisecond)

	// Establish two TCP connections
	conn1, err := net.Dial("tcp", "10.254.55.2:8080")
	if err != nil {
		t.Fatal(err)
	}
	defer conn1.Close()
	_, err = conn1.Write([]byte("test"))
	if err != nil {
		t.Fatal(err)
	}

	// Get conntrack flows
	flows, err := vishnetlink.ConntrackTableList(vishnetlink.ConntrackTable, vishnetlink.FAMILY_ALL)
	if err != nil {
		t.Fatalf("failed to list conntrack table: %v", err)
	}
	localTCP, ok := conn1.LocalAddr().(*net.TCPAddr)
	if !ok {
		t.Fatal("failed to get local TCP address")
	}

	var targetFlow *vishnetlink.ConntrackFlow
	for i := range flows {
		flow := flows[i]

		if flow.Forward.Protocol == syscall.IPPROTO_TCP &&
			flow.Forward.SrcIP.String() == localTCP.IP.String() &&
			flow.Forward.SrcPort == uint16(localTCP.Port) &&
			flow.Forward.DstIP.String() == "10.254.55.2" &&
			flow.Forward.DstPort == 8080 {
			targetFlow = flows[i]
			break
		}
	}

	if targetFlow == nil {
		t.Fatal("could not find target conntrack flow")
	}

	if targetFlow.ProtoInfo == nil {
		t.Fatal("target conntrack flow has no ProtoInfo")
	}
	if state, ok := targetFlow.ProtoInfo.(*vishnetlink.ProtoInfoTCP); ok && state.State != nl.TCP_CONNTRACK_ESTABLISHED {
		t.Fatalf("found target conntrack flow in state %d", state.State)
	}

	// Test seekAndDestroySocket
	packet := conntrack.PacketFromFlow(targetFlow)
	if packet == nil {
		t.Fatal("failed to generate packet from flow")
	}

	logs.GlogSetter("4")
	terminator := socket.NewSocketTerminator()
	if err := terminator.TerminateSocket(network.SwapPacket(packet)); err != nil {
		t.Fatalf("seekAndDestroySocket failed: %v", err)
	}

	// Verify the connection is broken
	_, err = conn1.Write([]byte("test"))
	if err == nil {
		t.Errorf("expected connection reset error, got %v", err)
	}

}

func TestFlushConntrackUDP(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges or unprivileged user namespaces")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	origns, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer origns.Close()

	rndString := make([]byte, 4)
	_, err = rand.Read(rndString)
	if err != nil {
		t.Errorf("fail to generate random name: %v", err)
	}
	nsName := fmt.Sprintf("ns%x", rndString)
	newns, err := netns.NewNamed(nsName)
	if err != nil {
		t.Fatalf("Failed to create network namespace: %v", err)
	}
	defer netns.DeleteNamed(nsName)
	defer newns.Close()

	// Return to original namespace
	if err := netns.Set(origns); err != nil {
		t.Fatal(err)
	}

	// Create a veth pair
	veth := &vishnetlink.Veth{
		LinkAttrs: vishnetlink.LinkAttrs{
			Name: "veth-root",
		},
		PeerName: "veth-ns",
	}

	_ = vishnetlink.LinkDel(veth) // Clean up if it already exists

	if err := vishnetlink.LinkAdd(veth); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := vishnetlink.LinkDel(veth); err != nil {
			t.Logf("failed to delete veth pair: %v", err)
		}
	}()
	t.Logf("created veth pair: %s <-> %s", veth.LinkAttrs.Name, veth.PeerName)

	// Move peer to the new namespace
	peer, err := vishnetlink.LinkByName("veth-ns")
	if err != nil {
		t.Fatal(err)
	}
	if err := vishnetlink.LinkSetNsFd(peer, int(newns)); err != nil {
		t.Fatal(err)
	}
	t.Logf("moved %s to new namespace", peer.Attrs().Name)

	// Configure root side
	rootLink, err := vishnetlink.LinkByName("veth-root")
	if err != nil {
		t.Fatal(err)
	}
	addrRoot, _ := vishnetlink.ParseAddr("10.254.55.1/29")
	if err := vishnetlink.AddrAdd(rootLink, addrRoot); err != nil {
		t.Fatal(err)
	}
	if err := vishnetlink.LinkSetUp(rootLink); err != nil {
		t.Fatal(err)
	}

	// Switch to new namespace to configure the other side
	if err := netns.Set(newns); err != nil {
		t.Fatal(err)
	}

	nsLink, err := vishnetlink.LinkByName("veth-ns")
	if err != nil {
		t.Fatal(err)
	}
	addrNs, err := vishnetlink.ParseAddr("10.254.55.2/29")
	if err != nil {
		t.Fatal(err)
	}
	if err := vishnetlink.AddrAdd(nsLink, addrNs); err != nil {
		t.Fatal(err)
	}
	if err := vishnetlink.LinkSetUp(nsLink); err != nil {
		t.Fatal(err)
	}
	t.Logf("configured %s with %s", nsLink.Attrs().Name, addrNs.String())

	// Return to original namespace
	if err := netns.Set(origns); err != nil {
		t.Fatal(err)
	}

	err = vishnetlink.RouteAdd(&vishnetlink.Route{
		LinkIndex: rootLink.Attrs().Index,
		Scope:     vishnetlink.SCOPE_HOST,
		Dst:       &net.IPNet{IP: net.IPv4(10, 254, 55, 2), Mask: net.CIDRMask(32, 32)},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Start UDP echo server in the new namespace.
	udpListener, err := ListenPacketInNamespace("udp", "10.254.55.2:8080", int(newns))
	if err != nil {
		t.Fatalf("ListenPacketInNamespace (UDP) failed: %v", err)
	}
	defer udpListener.Close()

	go func() {
		buf := make([]byte, 1024)
		for {
			n, addr, err := udpListener.ReadFrom(buf)
			if err != nil {
				return
			}
			udpListener.WriteTo(buf[:n], addr)
		}
	}()
	t.Log("UDP server started in namespace via helper")

	// Allow some time for servers to start
	time.Sleep(100 * time.Millisecond)

	// Establish a UDP connection
	conn, err := net.Dial("udp", "10.254.55.2:8080")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Send something to establish conntrack entry
	_, err = conn.Write([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	// and receive response
	buf := make([]byte, 1024)
	_, err = conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}

	// Get conntrack flows
	flows, err := vishnetlink.ConntrackTableList(vishnetlink.ConntrackTable, vishnetlink.FAMILY_ALL)
	if err != nil {
		t.Fatalf("failed to list conntrack table: %v", err)
	}

	var targetFlow *vishnetlink.ConntrackFlow
	for i := range flows {
		flow := flows[i]
		if flow.Forward.Protocol == syscall.IPPROTO_UDP &&
			flow.Forward.DstIP.String() == "10.254.55.2" &&
			flow.Forward.DstPort == 8080 {
			targetFlow = flows[i]
			break
		}
	}

	if targetFlow == nil {
		t.Fatal("could not find target conntrack flow")
	}

	// Flush conntrack table
	filter := conntrack.NewConntrackFilter([]*vishnetlink.ConntrackFlow{targetFlow})
	n, err := vishnetlink.ConntrackDeleteFilters(vishnetlink.ConntrackTable, unix.AF_INET, filter)
	if err != nil {
		t.Fatalf("failed to flush conntrack table: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected to delete 1 conntrack entry, deleted %d", n)
	}

	// Verify the flow is gone
	flows, err = vishnetlink.ConntrackTableList(vishnetlink.ConntrackTable, vishnetlink.FAMILY_ALL)
	if err != nil {
		t.Fatalf("failed to list conntrack table: %v", err)
	}

	for i := range flows {
		flow := flows[i]
		if flow.Forward.Protocol == syscall.IPPROTO_UDP &&
			flow.Forward.DstIP.String() == "10.254.55.2" &&
			flow.Forward.DstPort == 8080 {
			t.Fatal("target conntrack flow was not deleted")
		}
	}
}

// ListenInNamespace creates a net.Listener inside a specific network namespace.
// The 'nsFD' is the file descriptor for the target namespace (e.g., from /var/run/netns/myns).
func ListenInNamespace(network, address string, nsFD int) (net.Listener, error) {
	// Define the function to be executed inside the namespace.
	listenFunc := func() (net.Listener, error) {
		// This call to net.Listen will run inside the target namespace.
		return net.Listen(network, address)
	}

	return executeInNamespace(nsFD, listenFunc)
}

// ListenPacketInNamespace creates a net.PacketConn inside a specific network namespace.
func ListenPacketInNamespace(network, address string, nsFD int) (net.PacketConn, error) {
	listenFunc := func() (net.PacketConn, error) {
		return net.ListenPacket(network, address)
	}
	return executeInNamespace(nsFD, listenFunc)
}

// executeInNamespace runs a function 'fn' within a specific network namespace.
func executeInNamespace[T any](nsFD int, fn func() (T, error)) (T, error) {
	var zero T // The zero value of type T, to be returned on error.

	// Lock the goroutine to a single OS thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Get a handle to the original namespace to switch back later.
	originalNS, err := netns.Get()
	if err != nil {
		return zero, fmt.Errorf("failed to get current network namespace: %w", err)
	}
	defer originalNS.Close()
	// Switch to the target network namespace.
	if err := unix.Setns(nsFD, unix.CLONE_NEWNET); err != nil {
		return zero, fmt.Errorf("failed to set network namespace: %w", err)
	}
	// Defer switching back to the original namespace. This runs even if 'fn' panics.
	defer func() {
		_ = netns.Set(originalNS)
	}()

	// Now, execute the provided function inside the target namespace.
	return fn()
}
