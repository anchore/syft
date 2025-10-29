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

// dpkgYaml represents the structure of dpkg.yaml files found in base snaps
type dpkgYaml struct {
	PackageRepositories []packageRepository `yaml:"package-repositories"`
	Packages            []string            `yaml:"packages"`
}

type packageRepository struct {
	Type string `yaml:"type"`
	PPA  string `yaml:"ppa,omitempty"`
	URL  string `yaml:"url,omitempty"`
}

// parseBaseDpkgYaml parses dpkg.yaml files from base snaps
func parseBaseDpkgYaml(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var dpkg dpkgYaml

	decoder := yaml.NewDecoder(reader)
	if err := decoder.Decode(&dpkg); err != nil {
		return nil, nil, fmt.Errorf("failed to parse dpkg.yaml: %w", err)
	}

	var packages []pkg.Package

	snapMetadata := pkg.SnapEntry{
		SnapType: pkg.SnapTypeBase,
	}

	// Parse each package entry in "name=version" format
	for _, pkgEntry := range dpkg.Packages {
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

		// Handle architecture suffixes (e.g., "libssl1.1:amd64")
		if strings.Contains(name, ":") {
			archParts := strings.SplitN(name, ":", 2)
			name = archParts[0]
			snapMetadata.Architecture = archParts[1]
		}

		debPkg := newDebianPackageFromSnap(
			name,
			version,
			snapMetadata,
			reader.Location,
		)

		packages = append(packages, debPkg)
	}

	return packages, nil, nil
}
