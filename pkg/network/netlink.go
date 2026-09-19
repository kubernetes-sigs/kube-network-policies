// SPDX-License-Identifier: APACHE-2.0

package network

import (
	"errors"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// IsTransientNetlinkError reports whether err comes from the netlink socket
// rather than from the kernel rejecting the request. The request may have been
// applied, so the caller must not assume the kernel state is unchanged.
func IsTransientNetlinkError(err error) bool {
	var opErr *netlink.OpError
	if errors.As(err, &opErr) && (opErr.Timeout() || opErr.Temporary()) {
		return true
	}
	for _, errno := range []error{unix.EINTR, unix.EAGAIN, unix.ENOBUFS, unix.ENOMEM} {
		if errors.Is(err, errno) {
			return true
		}
	}
	return false
}
