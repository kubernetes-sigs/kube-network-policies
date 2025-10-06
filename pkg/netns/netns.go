package netns

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"k8s.io/klog/v2"
)

// By convention a named network namespace is an object at /var/run/netns/NAME that can be opened
// Ref: https://github.com/vishvananda/netns/issues/106
const bindMountPath = "/var/run/netns"

// GetNetByNsId searches for a named network namespace by its ID and returns its name.
// It is responsibility of the caller to close the returned NsHandle.
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
			klog.V(4).Infof("Failed to get namespace from path %s: %v", path, err)
			continue
		}

		id, err := netlink.GetNetNsIdByFd(int(nsHandle))
		if err != nil {
			klog.V(4).Infof("Failed to get NetNsId for namespace %s: %v", path, err)
			_ = nsHandle.Close()
			continue
		}
		if id == targetID {
			return nsHandle, nil
		}
		_ = nsHandle.Close() // Close handle if not the target
	}

	return -1, fmt.Errorf("no named namespace found with ID %d in %s", targetID, bindMountPath)
}
