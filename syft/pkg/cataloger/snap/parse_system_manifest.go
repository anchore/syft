package snap

import (
	"context"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// systemManifest represents the structure of manifest.yaml files found in system/gadget snaps
type systemManifest struct {
	Name                 string   `yaml:"name"`
	Version              string   `yaml:"version"`
	Base                 string   `yaml:"base"`
	Grade                string   `yaml:"grade"`
	Confinement          string   `yaml:"confinement"`
	PrimedStagePackages  []string `yaml:"primed-stage-packages"`
	Architectures        []string `yaml:"architectures"`
	SnapcraftVersion     string   `yaml:"snapcraft-version"`
	SnapcraftOSReleaseID string   `yaml:"snapcraft-os-release-id"`
}

// parseSystemManifest parses manifest.yaml files from system/gadget snaps
func parseSystemManifest(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var manifest systemManifest

	decoder := yaml.NewDecoder(reader)
	if err := decoder.Decode(&manifest); err != nil {
		return nil, nil, fmt.Errorf("failed to parse manifest.yaml: %w", err)
	}

	var packages []pkg.Package

	// Determine snap type - could be system, gadget, or app
	snapType := pkg.SnapTypeApp // Default
	if manifest.Name != "" {
		// Try to infer type from name patterns or content
		switch {
		case strings.Contains(strings.ToLower(manifest.Name), "gadget"):
			snapType = pkg.SnapTypeGadget
		default:
			snapType = pkg.SnapTypeApp // System snaps are often just regular apps
		}
	}

	snapMetadata := pkg.SnapEntry{
		SnapType:    snapType,
		Base:        manifest.Base,
		SnapName:    manifest.Name,
		SnapVersion: manifest.Version,
	}

	// Set architecture if available
	if len(manifest.Architectures) > 0 {
		snapMetadata.Architecture = manifest.Architectures[0]
	}

	// Parse primed-stage-packages entries
	for _, pkgEntry := range manifest.PrimedStagePackages {
		if !strings.Contains(pkgEntry, "=") {
			continue // Skip malformed entries
		}

		parts := strings.SplitN(pkgEntry, "=", 2)
		if len(parts) != 2 {
			continue
		}

		name := strings.TrimSpace(parts[0])
		version := strings.TrimSpace(parts[1])

		// Skip empty names or versions
		if name == "" || version == "" {
			continue
		}

		// Handle architecture suffixes if present
		currentMetadata := snapMetadata
		if strings.Contains(name, ":") {
			archParts := strings.SplitN(name, ":", 2)
			name = archParts[0]
			currentMetadata.Architecture = archParts[1]
		}

		debPkg := newDebianPackageFromSnap(
			name,
			version,
			currentMetadata,
			reader.Location,
		)

		packages = append(packages, debPkg)
	}

	return packages, nil, nil
}
