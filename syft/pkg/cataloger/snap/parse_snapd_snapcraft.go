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

// snapcraftYaml represents the structure of snapcraft.yaml files found in snapd snaps
type snapcraftYaml struct {
	Name         string                 `yaml:"name"`
	Version      string                 `yaml:"version"`
	Summary      string                 `yaml:"summary"`
	Description  string                 `yaml:"description"`
	Base         string                 `yaml:"base"`
	Grade        string                 `yaml:"grade"`
	Confinement  string                 `yaml:"confinement"`
	Architectures []string              `yaml:"architectures"`
	Parts        map[string]snapcraftPart `yaml:"parts"`
}

// snapcraftPart represents a part in a snapcraft.yaml file
type snapcraftPart struct {
	Plugin           string            `yaml:"plugin"`
	Source           string            `yaml:"source"`
	SourceType       string            `yaml:"source-type"`
	SourceTag        string            `yaml:"source-tag"`
	SourceCommit     string            `yaml:"source-commit"`
	BuildPackages    []string          `yaml:"build-packages"`
	StagePackages    []string          `yaml:"stage-packages"`
	BuildSnaps       []string          `yaml:"build-snaps"`
	StageSnaps       []string          `yaml:"stage-snaps"`
	BuildEnvironment []map[string]string `yaml:"build-environment"`
	Override         map[string]string `yaml:"override-build"`
}

// parseSnapdSnapcraft parses snapcraft.yaml files from snapd snaps
func parseSnapdSnapcraft(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var snapcraft snapcraftYaml

	decoder := yaml.NewDecoder(reader)
	if err := decoder.Decode(&snapcraft); err != nil {
		return nil, nil, fmt.Errorf("failed to parse snapcraft.yaml: %w", err)
	}

	var packages []pkg.Package

	snapMetadata := SnapMetadata{
		SnapType:    SnapTypeSnapd,
		Base:        snapcraft.Base,
		SnapName:    snapcraft.Name,
		SnapVersion: snapcraft.Version,
	}

	// Set architecture if available
	if len(snapcraft.Architectures) > 0 {
		snapMetadata.Architecture = snapcraft.Architectures[0]
	}

	// Parse packages from all parts
	for partName, part := range snapcraft.Parts {
		// Process build-packages
		for _, pkgName := range part.BuildPackages {
			if pkgName == "" {
				continue
			}

			// Build packages might not have explicit versions, use unknown
			buildPkg := newDebianPackageFromSnap(
				pkgName,
				"unknown",
				SnapMetadata{
					SnapType:     SnapTypeSnapd,
					Base:         snapcraft.Base,
					SnapName:     snapcraft.Name,
					SnapVersion:  snapcraft.Version,
					Architecture: snapMetadata.Architecture,
				},
				reader.Location,
			)

			packages = append(packages, buildPkg)
		}

		// Process stage-packages (these might have version constraints)
		for _, pkgEntry := range part.StagePackages {
			if pkgEntry == "" {
				continue
			}

			name := pkgEntry
			version := "unknown"

			// Handle version constraints like "package=version" or "package>=version"
			if strings.ContainsAny(pkgEntry, "=<>") {
				// Split on various version operators
				for _, op := range []string{">=", "<=", "==", "!=", "=", ">", "<"} {
					if strings.Contains(pkgEntry, op) {
						parts := strings.SplitN(pkgEntry, op, 2)
						if len(parts) == 2 {
							name = strings.TrimSpace(parts[0])
							version = strings.TrimSpace(parts[1])
							break
						}
					}
				}
			}

			stagePkg := newDebianPackageFromSnap(
				name,
				version,
				SnapMetadata{
					SnapType:     SnapTypeSnapd,
					Base:         snapcraft.Base,
					SnapName:     snapcraft.Name,
					SnapVersion:  snapcraft.Version,
					Architecture: snapMetadata.Architecture,
				},
				reader.Location,
			)

			packages = append(packages, stagePkg)
		}

		// Process build-snaps and stage-snaps as snap dependencies
		for _, snapName := range append(part.BuildSnaps, part.StageSnaps...) {
			if snapName == "" {
				continue
			}

			snapPkg := newPackage(
				snapName,
				"unknown",
				SnapMetadata{
					SnapType:     SnapTypeApp, // Assume app type for dependencies
					SnapName:     snapName,
					SnapVersion:  "unknown",
					Architecture: snapMetadata.Architecture,
				},
				reader.Location,
			)

			packages = append(packages, snapPkg)
		}

		// If part has source information, we could potentially track source dependencies
		// For now, we'll skip this as it's complex and may not provide much value
		_ = partName // Suppress unused variable warning
	}

	return packages, nil, nil
}