package python

import (
	"context"
	"fmt"
	"sort"

	"github.com/BurntSushi/toml"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
)

// integrity check
var _ generic.Parser = parsePoetryLock

type poetryPackageSource struct {
	URL       string `toml:"url"`
	Type      string `toml:"type"`
	Reference string `toml:"reference"`
}

type poetryPackages struct {
	Packages []poetryPackage `toml:"package"`
}

type poetryPackage struct {
	Name                  string                    `toml:"name"`
	Version               string                    `toml:"version"`
	Category              string                    `toml:"category"`
	Description           string                    `toml:"description"`
	Optional              bool                      `toml:"optional"`
	Source                poetryPackageSource       `toml:"source"`
	DependenciesUnmarshal map[string]toml.Primitive `toml:"dependencies"`
	Extras                map[string][]string       `toml:"extras"`
	Dependencies          map[string][]poetryPackageDependency
}

type poetryPackageDependency struct {
	Version  string   `toml:"version"`
	Markers  string   `toml:"markers"`
	Optional bool     `toml:"optional"`
	Extras   []string `toml:"extras"`
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
	return pkgs, dependency.Resolve(poetryLockDependencySpecifier, pkgs), unknown.IfEmptyf(pkgs, "unable to determine packages")
}

func poetryLockPackages(reader file.LocationReadCloser) ([]pkg.Package, error) {
	metadata := poetryPackages{}
	md, err := toml.NewDecoder(reader).Decode(&metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to read poetry lock package: %w", err)
	}

	for i, p := range metadata.Packages {
		dependencies := make(map[string][]poetryPackageDependency)
		for pkgName, du := range p.DependenciesUnmarshal {
			var (
				single    string
				singleObj poetryPackageDependency
				multiObj  []poetryPackageDependency
			)

			switch {
			case md.PrimitiveDecode(du, &single) == nil:
				dependencies[pkgName] = append(dependencies[pkgName], poetryPackageDependency{Version: single})
			case md.PrimitiveDecode(du, &singleObj) == nil:
				dependencies[pkgName] = append(dependencies[pkgName], singleObj)
			case md.PrimitiveDecode(du, &multiObj) == nil:
				dependencies[pkgName] = append(dependencies[pkgName], multiObj...)
			default:
				log.Tracef("failed to decode poetry lock package dependencies for %s; skipping", pkgName)
			}
		}
		metadata.Packages[i].Dependencies = dependencies
	}

	var pkgs []pkg.Package
	for _, p := range metadata.Packages {
		pkgs = append(
			pkgs,
			newPackageForIndexWithMetadata(
				p.Name,
				p.Version,
				newPythonPoetryLockEntry(p),
				reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
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
	for name, dependencies := range p.Dependencies {
		for _, d := range dependencies {
			deps = append(deps, pkg.PythonPoetryLockDependencyEntry{
				Name:    name,
				Version: d.Version,
				Extras:  d.Extras,
				Markers: d.Markers,
			})
		}
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
