package capabilities

import (
	_ "embed"
	"fmt"
	"sort"

	"github.com/scylladb/go-set/strset"
	"gopkg.in/yaml.v3"

	"github.com/anchore/syft/internal/task"
)

//go:embed packages.yaml
var catalogersYAML []byte

// LoadDocument loads and returns the complete document including configs and app-configs
func LoadDocument() (*Document, error) {
	var doc Document
	if err := yaml.Unmarshal(catalogersYAML, &doc); err != nil {
		return nil, fmt.Errorf("failed to parse embedded capabilities YAML: %w", err)
	}
	return &doc, nil
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
