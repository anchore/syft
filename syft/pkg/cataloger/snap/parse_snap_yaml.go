package snap

import (
	"context"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// snapYaml represents the structure of meta/snap.yaml files
type snapYaml struct {
	Name         string `yaml:"name"`
	Version      string `yaml:"version"`
	Base         string `yaml:"base"`
	Type         string `yaml:"type"`
	Architecture string `yaml:"architecture"`
	Summary      string `yaml:"summary"`
	Description  string `yaml:"description"`
}

// parseSnapYaml parses meta/snap.yaml files to identify snap type and basic metadata
func parseSnapYaml(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var snap snapYaml

	decoder := yaml.NewDecoder(reader)
	if err := decoder.Decode(&snap); err != nil {
		return nil, nil, fmt.Errorf("failed to parse snap.yaml: %w", err)
	}

	if snap.Name == "" {
		return nil, nil, fmt.Errorf("snap.yaml missing required 'name' field")
	}

	// Determine snap type - default to "app" if not specified
	snapType := snap.Type
	if snapType == "" {
		snapType = pkg.SnapTypeApp
	}

	metadata := pkg.SnapEntry{
		SnapType:     snapType,
		Base:         snap.Base,
		SnapName:     snap.Name,
		SnapVersion:  snap.Version,
		Architecture: snap.Architecture,
	}

	// Create a package representing the snap itself
	snapPkg := newPackage(
		snap.Name,
		snap.Version,
		metadata,
		reader.Location,
	)

	return []pkg.Package{snapPkg}, nil, nil
}

// readAll reads all content from a reader and returns it as bytes
func readAll(r io.Reader) ([]byte, error) {
	return io.ReadAll(r)
}
