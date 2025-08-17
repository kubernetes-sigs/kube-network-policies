package plugin

import (
	"fmt"
	"os"
	"path/filepath"
	"plugin"
	"sort"
	"strconv"
	"strings"

	"k8s.io/klog/v2"
	"sigs.k8s.io/kube-network-policies/pkg/api"
)

type LoadedPlugin struct {
	Index     int
	Name      string
	Evaluator api.PolicyEvaluator
}

func LoadPlugins(pluginDir string, dependencies map[string]interface{}) ([]LoadedPlugin, error) {
	var loadedPlugins []LoadedPlugin

	files, err := os.ReadDir(pluginDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read plugin directory %s: %w", pluginDir, err)
	}

	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".so") {
			continue
		}

		// Parse filename for index and name
		parts := strings.SplitN(strings.TrimSuffix(file.Name(), ".so"), "-", 2)
		if len(parts) != 2 {
			klog.Warningf("Skipping plugin with invalid filename format: %s", file.Name())
			continue
		}

		index, err := strconv.Atoi(parts[0])
		if err != nil {
			klog.Warningf("Skipping plugin with invalid index: %s", file.Name())
			continue
		}
		name := parts[1]

		// Load the plugin
		pluginPath := filepath.Join(pluginDir, file.Name())
		p, err := plugin.Open(pluginPath)
		if err != nil {
			klog.Errorf("Failed to open plugin %s: %v", pluginPath, err)
			continue
		}

		// Look up the 'New' symbol
		newFuncSymbol, err := p.Lookup("New")
		if err != nil {
			klog.Errorf("Plugin %s does not export a 'New' function: %v", name, err)
			continue
		}

		// Assert the symbol's type
		newFunc, ok := newFuncSymbol.(func(map[string]interface{}) (api.PolicyEvaluator, error))
		if !ok {
			klog.Errorf("Plugin %s's 'New' function has the wrong signature", name)
			continue
		}

		// Create the evaluator instance
		evaluator, err := newFunc(dependencies)
		if err != nil {
			klog.Errorf("Failed to initialize plugin %s: %v", name, err)
			continue
		}

		loadedPlugins = append(loadedPlugins, LoadedPlugin{
			Index:     index,
			Name:      name,
			Evaluator: evaluator,
		})
		klog.Infof("Successfully loaded plugin: %s (index: %d)", name, index)
	}

	// Sort plugins by index
	sort.Slice(loadedPlugins, func(i, j int) bool {
		return loadedPlugins[i].Index < loadedPlugins[j].Index
	})

	return loadedPlugins, nil
}
