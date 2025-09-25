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
	Name          string                   `yaml:"name"`
	Version       string                   `yaml:"version"`
	Summary       string                   `yaml:"summary"`
	Description   string                   `yaml:"description"`
	Base          string                   `yaml:"base"`
	Grade         string                   `yaml:"grade"`
	Confinement   string                   `yaml:"confinement"`
	Architectures []string                 `yaml:"architectures"`
	Parts         map[string]snapcraftPart `yaml:"parts"`
}

// snapcraftPart represents a part in a snapcraft.yaml file
type snapcraftPart struct {
	Plugin           string              `yaml:"plugin"`
	Source           string              `yaml:"source"`
	SourceType       string              `yaml:"source-type"`
	SourceTag        string              `yaml:"source-tag"`
	SourceCommit     string              `yaml:"source-commit"`
	BuildPackages    []string            `yaml:"build-packages"`
	StagePackages    []string            `yaml:"stage-packages"`
	BuildSnaps       []string            `yaml:"build-snaps"`
	StageSnaps       []string            `yaml:"stage-snaps"`
	BuildEnvironment []map[string]string `yaml:"build-environment"`
	Override         map[string]string   `yaml:"override-build"`
}

// parseSnapdSnapcraft parses snapcraft.yaml files from snapd snaps
func parseSnapdSnapcraft(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var snapcraft snapcraftYaml

	decoder := yaml.NewDecoder(reader)
	if err := decoder.Decode(&snapcraft); err != nil {
		return nil, nil, fmt.Errorf("failed to parse snapcraft.yaml: %w", err)
	}

	snapMetadata := createMetadata(snapcraft)
	packages := extractPackagesFromParts(snapcraft, snapMetadata, reader.Location)

	return packages, nil, nil
}

// createMetadata creates metadata from snapcraft.yaml
func createMetadata(snapcraft snapcraftYaml) pkg.SnapEntry {
	metadata := pkg.SnapEntry{
		SnapType:    pkg.SnapTypeSnapd,
		Base:        snapcraft.Base,
		SnapName:    snapcraft.Name,
		SnapVersion: snapcraft.Version,
	}

	if len(snapcraft.Architectures) > 0 {
		metadata.Architecture = snapcraft.Architectures[0]
	}

	return metadata
}

// extractPackagesFromParts processes all parts to extract packages
func extractPackagesFromParts(snapcraft snapcraftYaml, baseMetadata pkg.SnapEntry, location file.Location) []pkg.Package {
	var packages []pkg.Package

	for _, part := range snapcraft.Parts {
		buildPackages := processBuildPackages(part.BuildPackages, baseMetadata, location)
		packages = append(packages, buildPackages...)

		stagePackages := processStagePackages(part.StagePackages, baseMetadata, location)
		packages = append(packages, stagePackages...)

		snapPackages := processSnapPackages(part.BuildSnaps, part.StageSnaps, baseMetadata, location)
		packages = append(packages, snapPackages...)
	}

	return packages
}

// processBuildPackages creates packages from build-packages list
func processBuildPackages(buildPackages []string, metadata pkg.SnapEntry, location file.Location) []pkg.Package {
	var packages []pkg.Package

	for _, pkgName := range buildPackages {
		if pkgName == "" {
			continue
		}

		buildPkg := newDebianPackageFromSnap(
			pkgName,
			"unknown",
			metadata,
			location,
		)
		packages = append(packages, buildPkg)
	}

	return packages
}

// processStagePackages creates packages from stage-packages list with version parsing
func processStagePackages(stagePackages []string, metadata pkg.SnapEntry, location file.Location) []pkg.Package {
	var packages []pkg.Package

	for _, pkgEntry := range stagePackages {
		if pkgEntry == "" {
			continue
		}

		name, version := parsePackageWithVersion(pkgEntry)
		stagePkg := newDebianPackageFromSnap(
			name,
			version,
			metadata,
			location,
		)
		packages = append(packages, stagePkg)
	}

	return packages
}

// parsePackageWithVersion extracts package name and version from version-constrained entries
func parsePackageWithVersion(pkgEntry string) (string, string) {
	name := pkgEntry
	version := "unknown"

	if !strings.ContainsAny(pkgEntry, "=<>") {
		return name, version
	}

	// Try to split on version operators
	operators := []string{">=", "<=", "==", "!=", "=", ">", "<"}
	for _, op := range operators {
		if strings.Contains(pkgEntry, op) {
			parts := strings.SplitN(pkgEntry, op, 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
			}
		}
	}

	return name, version
}

// processSnapPackages creates packages from snap dependencies
func processSnapPackages(buildSnaps, stageSnaps []string, baseMetadata pkg.SnapEntry, location file.Location) []pkg.Package {
	var packages []pkg.Package
	allSnaps := make([]string, 0, len(buildSnaps)+len(stageSnaps))
	allSnaps = append(allSnaps, buildSnaps...)
	allSnaps = append(allSnaps, stageSnaps...)

	for _, snapName := range allSnaps {
		if snapName == "" {
			continue
		}

		snapMetadata := pkg.SnapEntry{
			SnapType:     pkg.SnapTypeApp,
			SnapName:     snapName,
			SnapVersion:  "unknown",
			Architecture: baseMetadata.Architecture,
		}

		snapPkg := newPackage(
			snapName,
			"unknown",
			snapMetadata,
			location,
		)
		packages = append(packages, snapPkg)
	}

	return packages
}
