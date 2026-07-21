package internal

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/anchore/syft/internal/capabilities"
)

// LoadCapabilities loads the capabilities document from a YAML file.
// Returns both the parsed document and the original YAML node tree to preserve comments.
// Exported for use by the generator in generate/main.go
func LoadCapabilities(catalogerDir, repoRoot string) (*capabilities.Document, map[string]*yaml.Node, error) {
	// load all cataloger/*/capabilities.yaml files
	files, err := filepath.Glob(filepath.Join(catalogerDir, "*", CapabilitiesFilename))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to glob capabilities files: %w", err)
	}

	mergedDoc := &capabilities.Document{
		Configs:    make(map[string]capabilities.CatalogerConfigEntry),
		Catalogers: []capabilities.CatalogerEntry{},
	}
	nodeMap := make(map[string]*yaml.Node)

	// load each package file
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read %s: %w", file, err)
		}

		// parse into node tree to preserve comments
		var rootNode yaml.Node
		if err := yaml.Unmarshal(data, &rootNode); err != nil {
			return nil, nil, fmt.Errorf("failed to parse %s into node tree: %w", file, err)
		}

		// parse into struct
		var doc struct {
			Configs    map[string]capabilities.CatalogerConfigEntry `yaml:"configs"`
			Catalogers []capabilities.CatalogerEntry                `yaml:"catalogers"`
		}
		if err := yaml.Unmarshal(data, &doc); err != nil {
			fmt.Printf("\n=== DEBUG: YAML Parse Error in %s ===\n", file)
			fmt.Printf("Error: %v\n\n", err)
			fmt.Printf("=== FULL FILE CONTENT ===\n%s\n=== END FILE ===\n", string(data))
			return nil, nil, fmt.Errorf("failed to parse %s into struct: %w", file, err)
		}

		// merge configs
		for k, v := range doc.Configs {
			mergedDoc.Configs[k] = v
		}

		// merge catalogers
		mergedDoc.Catalogers = append(mergedDoc.Catalogers, doc.Catalogers...)

		// store node tree by ecosystem directory name
		// path is like "/path/to/syft/pkg/cataloger/alpine/capabilities.yaml"
		ecosystem := filepath.Base(filepath.Dir(file))
		nodeMap[ecosystem] = &rootNode
	}

	// load appconfig.yaml separately (from internal/capabilities/)
	appconfigPath := AppconfigPath(repoRoot)
	if _, err := os.Stat(appconfigPath); err == nil {
		data, err := os.ReadFile(appconfigPath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read appconfig.yaml: %w", err)
		}

		var appDoc struct {
			Application []capabilities.ApplicationConfigField `yaml:"application"`
		}
		if err := yaml.Unmarshal(data, &appDoc); err != nil {
			return nil, nil, fmt.Errorf("failed to parse appconfig.yaml: %w", err)
		}

		mergedDoc.ApplicationConfig = appDoc.Application

		// load node tree for appconfig
		var appNode yaml.Node
		if err := yaml.Unmarshal(data, &appNode); err != nil {
			return nil, nil, fmt.Errorf("failed to parse appconfig.yaml into node tree: %w", err)
		}
		nodeMap["appconfig"] = &appNode
	}

	return mergedDoc, nodeMap, nil
}
