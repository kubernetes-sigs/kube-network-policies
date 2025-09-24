package netns

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// By convention a named network namespace is an object at /var/run/netns/NAME that can be opened
// Ref: https://github.com/vishvananda/netns/issues/106
const bindMountPath = "/var/run/netns"

// GetNetByNsId searches for a named network namespace by its ID and returns its name.
func GetNetByNsId(targetID int) (netns.NsHandle, error) {
	entries, err := os.ReadDir(bindMountPath)
	if err != nil {
		if os.IsNotExist(err) {
			// If the directory doesn't exist, no named namespaces can be found.
			return -1, fmt.Errorf("no named namespace found with ID %d: directory %s does not exist", targetID, bindMountPath)
		}
		return -1, fmt.Errorf("could not read %s: %w", bindMountPath, err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		path := filepath.Join(bindMountPath, entry.Name())

		nsHandle, err := netns.GetFromPath(path)
		if err != nil {
			return -1, fmt.Errorf("failed to get netns handle for path %s: %w", path, err)
		}

		id, err := netlink.GetNetNsIdByFd(int(nsHandle))
		if err != nil {
			_ = nsHandle.Close()
			return -1, fmt.Errorf("failed to get netns ID for fd %d: %w", int(nsHandle), err)
		}
		if id == targetID {
			return nsHandle, nil
		}
		_ = nsHandle.Close() // Close handle if not the target
	}

	return -1, fmt.Errorf("no named namespace found with ID %d in %s", targetID, bindMountPath)
}
