package python

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/pelletier/go-toml"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
)

// integrity check
var _ generic.Parser = parsePoetryLock

type poetryPackageSource struct {
	URL string `toml:"url"`
}

type poetryPackages struct {
	Packages []poetryPackage `toml:"package"`
}

type poetryPackage struct {
	Name         string                             `toml:"name"`
	Version      string                             `toml:"version"`
	Category     string                             `toml:"category"`
	Description  string                             `toml:"description"`
	Optional     bool                               `toml:"optional"`
	Source       poetryPackageSource                `toml:"source"`
	Dependencies map[string]poetryPackageDependency `toml:"dependencies"`
	Extras       map[string][]string                `toml:"extras"`
}

type poetryPackageDependency struct {
	Version  string   `toml:"version"`
	Markers  string   `toml:"markers"`
	Optional bool     `toml:"optional"`
	Extras   []string `toml:"extras"`
}

func (d *poetryPackageDependency) UnmarshalText(data []byte) error {
	// attempt to parse as a map first
	var dep map[string]interface{}
	if err := toml.Unmarshal(data, &dep); err == nil {
		if extras, ok := dep["extras"]; ok {
			if extrasList, ok := extras.([]string); ok {
				d.Extras = extrasList
			}
		}

		if markers, ok := dep["markers"]; ok {
			if markersString, ok := markers.(string); ok {
				d.Markers = markersString
			}
		}

		if version, ok := dep["version"]; ok {
			if versionString, ok := version.(string); ok {
				d.Version = versionString
			}
		}
		return nil
	}

	if strings.ContainsAny(string(data), "[]{}") {
		// odds are this is really a malformed toml array or object
		return fmt.Errorf("unable to parse poetry dependency: version is malformed array/object: %q", string(data))
	}

	// assume this is a simple version string
	d.Version = string(data)

	return nil
}

// parsePoetryLock is a parser function for poetry.lock contents, returning all python packages discovered.
func parsePoetryLock(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	pkgs, err := poetryLockPackages(reader)
	if err != nil {
		return nil, nil, err
	}

	// since we would never expect to create relationships for packages across multiple poetry.lock files
	// we should do this on a file parser level (each poetry.lock) instead of a cataloger level (across all
	// poetry.lock files)
	return pkgs, dependency.Resolve(poetryLockDependencySpecifier, pkgs), nil
}

func poetryLockPackages(reader file.LocationReadCloser) ([]pkg.Package, error) {
	tree, err := toml.LoadReader(reader)
	if err != nil {
		return nil, fmt.Errorf("unable to load poetry.lock for parsing: %w", err)
	}

	metadata := poetryPackages{}
	err = tree.Unmarshal(&metadata)
	if err != nil {
		return nil, fmt.Errorf("unable to parse poetry.lock: %w", err)
	}

	var pkgs []pkg.Package
	for _, p := range metadata.Packages {
		pkgs = append(
			pkgs,
			newPackageForIndexWithMetadata(
				p.Name,
				p.Version,
				newPythonPoetryLockEntry(p),
				reader.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
			),
		)
	}
	return pkgs, nil
}

func newPythonPoetryLockEntry(p poetryPackage) pkg.PythonPoetryLockEntry {
	return pkg.PythonPoetryLockEntry{
		Index:        extractIndex(p),
		Dependencies: extractPoetryDependencies(p),
		Extras:       extractPoetryExtras(p),
	}
}

func extractIndex(p poetryPackage) string {
	if p.Source.URL != "" {
		return p.Source.URL
	}
	// https://python-poetry.org/docs/repositories/
	return "https://pypi.org/simple"
}

func extractPoetryDependencies(p poetryPackage) []pkg.PythonPoetryLockDependencyEntry {
	var deps []pkg.PythonPoetryLockDependencyEntry
	for name, dep := range p.Dependencies {
		deps = append(deps, pkg.PythonPoetryLockDependencyEntry{
			Name:    name,
			Version: dep.Version,
			Extras:  dep.Extras,
			Markers: dep.Markers,
		})
	}
	sort.Slice(deps, func(i, j int) bool {
		return deps[i].Name < deps[j].Name
	})
	return deps
}

func extractPoetryExtras(p poetryPackage) []pkg.PythonPoetryLockExtraEntry {
	var extras []pkg.PythonPoetryLockExtraEntry
	for name, deps := range p.Extras {
		extras = append(extras, pkg.PythonPoetryLockExtraEntry{
			Name:         name,
			Dependencies: deps,
		})
	}
	sort.Slice(extras, func(i, j int) bool {
		return extras[i].Name < extras[j].Name
	})
	return extras
}
