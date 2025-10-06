package socket

import (
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
	v1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
	pkgnetns "sigs.k8s.io/kube-network-policies/pkg/netns"
	"sigs.k8s.io/kube-network-policies/pkg/network"

	"github.com/vishvananda/netlink"
)

// SocketTerminator provides functionality to find and destroy TCP sockets,
// automatically discovering the correct network namespace.
type SocketTerminator struct{}

// NewSocketTerminator creates a new instance of the SocketTerminator.
func NewSocketTerminator() *SocketTerminator {
	return &SocketTerminator{}
}

// terminate connections regardless of which direction the packet was captured from.
func (st *SocketTerminator) TerminateSocket(p *network.Packet) error {
	if p == nil {
		return fmt.Errorf("nil packet provided")
	}

	// Define the action to be performed once the correct namespace is found.
	callback := func(nh *netlink.Handle) error {
		return st.destroyTCPSocket(nh, p)
	}

	// First, attempt to find and terminate using the source IP.
	err := st.findAndExecuteInNS(p.SrcIP, callback)
	if err == nil {
		return nil
	}

	// If the first attempt failed, check if it was because the source IP was not local.
	if errors.Is(err, unix.ESRCH) {
		klog.V(4).Infof("Could not find route for SrcIP %s, retrying with DstIP %s", p.SrcIP, p.DstIP)
		return nil
	}

	return fmt.Errorf("failed to terminate socket for packet %s: %w", p.String(), err)
}

// findAndExecuteInNS is a helper that finds the correct namespace for a given IP,
// creates a netlink handle within it, executes a callback function with that handle,
// and ensures all resources are cleaned up.
func (st *SocketTerminator) findAndExecuteInNS(ip net.IP, callback func(nh *netlink.Handle) error) error {
	if ip == nil {
		return fmt.Errorf("nil IP provided")
	}
	klog.V(4).Infof("Finding route for IP: %s", ip)

	routes, err := netlink.RouteGet(ip)
	if err != nil {
		// Use ESRCH to indicate that the process (or in this case, route) could not be found.
		return fmt.Errorf("failed to get route for IP %s: %w", ip.String(), unix.ESRCH)
	}
	if len(routes) == 0 {
		return fmt.Errorf("no route found for IP %s: %w", ip.String(), unix.ESRCH)
	}
	klog.V(4).Infof("Found routes for IP %s: %+v", ip, routes)

	// Iterate through routes to find one associated with a veth pair in a namespace.
	for _, route := range routes {
		if route.LinkIndex == 0 {
			continue
		}

		link, err := netlink.LinkByIndex(route.LinkIndex)
		if err != nil {
			klog.V(4).Infof("Failed to get link by index %d: %v", route.LinkIndex, err)
			continue
		}

		iface, ok := link.(*netlink.Veth)
		if !ok {
			klog.V(4).Infof("Link %s is not a veth interface, skipping.", link.Attrs().Name)
			continue
		}
		klog.V(4).Infof("Found veth interface %s with NetNsID %d", iface.Name, iface.NetNsID)

		// Get the namespace handle and execute the callback.
		return st.executeInNS(iface.NetNsID, callback)
	}

	// If no suitable veth/namespace was found, return an error.
	return fmt.Errorf("no veth interface found in routes for IP %s: %w", ip.String(), unix.ESRCH)
}

// executeInNS gets a handle for a specific nsID and runs the callback.
// It ensures all netlink and namespace handles are closed.
func (st *SocketTerminator) executeInNS(nsID int, callback func(nh *netlink.Handle) error) error {
	if nsID < 0 {
		// Use the host namespace
		return fmt.Errorf("can not be executed in host namespace")
	}
	nsHandle, err := pkgnetns.GetNetByNsId(nsID)
	if err != nil {
		return fmt.Errorf("failed to get handle for nsID %d netns %s : %w", nsID, nsHandle.String(), err)
	}
	defer nsHandle.Close()

	nh, err := netlink.NewHandleAt(nsHandle, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return fmt.Errorf("failed to create netlink handle for nsID %d: %w", nsID, err)
	}
	defer nh.Close()

	klog.V(4).Infof("Executing callback in namespace ID %d", nsID)
	return callback(nh)
}

// destroyTCPSocket uses a netlink handle to terminate a TCP connection.
func (st *SocketTerminator) destroyTCPSocket(nh *netlink.Handle, p *network.Packet) error {
	klog.V(4).Infof("Attempting to destroy socket for packet %s", p.String())

	if p.Proto != v1.ProtocolTCP {
		return nil // Not a TCP packet, nothing to do.
	}

	local := &net.TCPAddr{IP: p.SrcIP, Port: p.SrcPort}
	remote := &net.TCPAddr{IP: p.DstIP, Port: p.DstPort}

	klog.V(2).Infof("Attempting to destroy socket: %s -> %s", local, remote)
	err := nh.SocketDestroy(local, remote)
	if errors.Is(err, unix.ENOENT) {
		klog.V(4).Infof("Socket %s -> %s already gone (ENOENT), ignoring.", local, remote)
		return nil // Success, the socket does not exist.
	}
	if err != nil {
		return fmt.Errorf("failed to destroy socket %s -> %s: %w", local, remote, err)
	}

	klog.V(2).Infof("Successfully destroyed socket: %s -> %s", local, remote)
	return nil
}
