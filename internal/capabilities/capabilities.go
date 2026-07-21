// Package capabilities provides discovery and tracking of cataloger capabilities.
package capabilities

import (
	"embed"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"

	"github.com/scylladb/go-set/strset"
	"gopkg.in/yaml.v3"

	"github.com/anchore/syft/internal/task"
)

//go:generate go run ./generate

//go:embed appconfig.yaml
var appconfigYAML []byte

var catalogerFiles *embed.FS

func RegisterCatalogerFiles(f embed.FS) {
	catalogerFiles = &f
}

// LoadDocument loads and returns the complete document including configs and app-configs
func LoadDocument() (*Document, error) {
	if catalogerFiles == nil {
		return nil, fmt.Errorf("cataloger files not registered")
	}

	// parse application config
	var appDoc struct {
		Application []ApplicationConfigField `yaml:"application"`
	}
	if err := yaml.Unmarshal(appconfigYAML, &appDoc); err != nil {
		return nil, fmt.Errorf("failed to parse appconfig.yaml: %w", err)
	}

	// walk the embedded filesystem to find all cataloger capabilities.yaml files
	var catalogersDoc Document
	catalogersDoc.ApplicationConfig = appDoc.Application
	catalogersDoc.Configs = make(map[string]CatalogerConfigEntry)

	err := fs.WalkDir(catalogerFiles, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// skip non-yaml files and directories
		if d.IsDir() || filepath.Ext(path) != ".yaml" || path == "." {
			return nil
		}

		// read the file
		data, err := catalogerFiles.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", path, err)
		}

		// parse the file
		var capDoc struct {
			Configs    map[string]CatalogerConfigEntry `yaml:"configs"`
			Catalogers []CatalogerEntry                `yaml:"catalogers"`
		}
		if err := yaml.Unmarshal(data, &capDoc); err != nil {
			return fmt.Errorf("failed to parse %s: %w", path, err)
		}

		// merge configs
		for k, v := range capDoc.Configs {
			catalogersDoc.Configs[k] = v
		}

		// merge catalogers
		catalogersDoc.Catalogers = append(catalogersDoc.Catalogers, capDoc.Catalogers...)

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk cataloger capabilities: %w", err)
	}

	// sort catalogers by name for consistency
	sort.Slice(catalogersDoc.Catalogers, func(i, j int) bool {
		return catalogersDoc.Catalogers[i].Name < catalogersDoc.Catalogers[j].Name
	})

	return &catalogersDoc, nil
}

// Packages loads and returns all cataloger capabilities from the embedded YAML file
func Packages() ([]CatalogerEntry, error) {
	doc, err := LoadDocument()
	if err != nil {
		return nil, err
	}
	return doc.Catalogers, nil
}

// CatalogerInfo represents a cataloger's name and selection tags
type CatalogerInfo struct {
	Name      string
	Selectors []string // tags for cataloger name selection
}

// ExtractCatalogerInfo extracts cataloger names and their selection tags from tasks
func ExtractCatalogerInfo(tasks []task.Task) []CatalogerInfo {
	var infos []CatalogerInfo

	for _, tsk := range tasks {
		var selectors []string
		name := tsk.Name()

		if s, ok := tsk.(task.Selector); ok {
			set := strset.New(s.Selectors()...)
			set.Remove(name)
			selectors = set.List()
			sort.Strings(selectors)
		}

		infos = append(infos, CatalogerInfo{
			Name:      name,
			Selectors: selectors,
		})
	}

	return infos
}
