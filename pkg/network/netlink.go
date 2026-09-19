// SPDX-License-Identifier: APACHE-2.0

package network

import (
	"errors"
	"syscall"

	"github.com/mdlayher/netlink"
)

// IsNetlinkRejection reports whether err is an error the kernel sent in reply
// to a netlink request: the request was rejected and nothing was applied, so
// the caller can send a different request. Any other error (a failed system
// call, a deadline) means the reply was not read and the request may have been
// applied, the caller can only retry the same request later.
//
// mdlayher/netlink sets a bare errno for an error message from the kernel and
// wraps system call errors in *os.SyscallError.
func IsNetlinkRejection(err error) bool {
	var opErr *netlink.OpError
	if !errors.As(err, &opErr) {
		return false
	}
	_, ok := opErr.Err.(syscall.Errno)
	return ok
}
