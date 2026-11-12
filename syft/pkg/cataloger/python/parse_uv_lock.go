package python

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"maps"
	"slices"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
)

// We use this to check for the version before we try to parse.
// The TOML library handily ignores everything that isn't mentioend in the struct.
type uvLockFileVersion struct {
	Version  int `toml:"version"`
	Revision int `toml:"revision"`
}

type uvLockFile struct {
	Version        int         `toml:"version"`
	Revision       int         `toml:"revision"`
	RequiresPython string      `toml:"requires-python"`
	Packages       []uvPackage `toml:"package"`
}

type uvPackage struct {
	Name                 string                    `toml:"name"`
	Version              string                    `toml:"version"`
	Source               map[string]string         `toml:"source"` // Possible key values for Source are: registry, git, direct, path, directory, editable, virtual
	Dependencies         uvDependencies            `toml:"dependencies"`
	DevDependencies      map[string]uvDependencies `toml:"dev-dependencies"`
	OptionalDependencies map[string]uvDependencies `toml:"optional-dependencies"`
	Sdist                uvDistribution            `toml:"sdist"`
	Wheels               []uvDistribution          `toml:"wheels"`
	Metadata             uvMetadata                `toml:"metadata"`
}

type uvDependencies []uvDependency

type uvDependency struct {
	Name string `toml:"name"`
	// Version is only written by uv when more than one version of this name is locked
	Version string   `toml:"version"`
	Extras  []string `toml:"extra"`
	Markers string   `toml:"marker"`
}

type uvDistribution struct {
	URL  string `toml:"url"`
	Hash string `toml:"hash"`
	Size int    `toml:"size"`
}

type uvRequiresDist []struct {
	Name      string   `toml:"name"`
	Markers   string   `toml:"marker"`
	Extras    []string `toml:"extras"`
	Specifier string   `toml:"specifier"`
}

type uvMetadata struct {
	RequiresDist   uvRequiresDist `toml:"requires-dist"`
	ProvidesExtras []string       `toml:"provides-extras"`
}

type uvLockParser struct {
	cfg             CatalogerConfig
	licenseResolver pythonLicenseResolver
}

func newUvLockParser(cfg CatalogerConfig) uvLockParser {
	return uvLockParser{
		cfg:             cfg,
		licenseResolver: newPythonLicenseResolver(cfg),
	}
}

// parseUvLock is a parser function for uv.lock contents, returning all the pakcages discovered
func (ulp uvLockParser) parseUvLock(ctx context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	pkgs, specs, err := ulp.uvLockPackages(ctx, reader)
	if err != nil {
		return nil, nil, err
	}

	specifier := func(p pkg.Package) dependency.Specification {
		return specs[p.ID()]
	}

	return pkgs, dependency.Resolve(specifier, pkgs), err
}

func extractUvIndex(p uvPackage) string {
	// This is a map, but there should only be one key, value pair
	var rvalue string
	for _, value := range p.Source {
		rvalue = value
	}

	return rvalue
}

func extractUvDependencies(p uvPackage) []pkg.PythonUvLockDependencyEntry {
	var deps []pkg.PythonUvLockDependencyEntry
	for _, d := range p.Dependencies {
		deps = append(deps, pkg.PythonUvLockDependencyEntry{
			Name:    d.Name,
			Extras:  d.Extras,
			Markers: d.Markers,
		})
	}
	sort.Slice(deps, func(i, j int) bool {
		return deps[i].Name < deps[j].Name
	})
	return deps
}

func extractUvExtras(p uvPackage) []pkg.PythonUvLockExtraEntry {
	var extras []pkg.PythonUvLockExtraEntry
	for name, depsStruct := range p.OptionalDependencies {
		var extraDeps []string
		for _, deps := range depsStruct {
			extraDeps = append(extraDeps, deps.Name)
		}
		extras = append(extras, pkg.PythonUvLockExtraEntry{
			Name:         name,
			Dependencies: extraDeps,
		})
	}
	return extras
}

func newPythonUvLockEntry(p uvPackage) pkg.PythonUvLockEntry {
	return pkg.PythonUvLockEntry{
		Index:        extractUvIndex(p),
		Dependencies: extractUvDependencies(p),
		Extras:       extractUvExtras(p),
	}
}

// uvLockPackages returns the packages in the lock along with the dependency specification for each (by package ID).
func (ulp uvLockParser) uvLockPackages(ctx context.Context, reader file.LocationReadCloser) ([]pkg.Package, map[artifact.ID]dependency.Specification, error) {
	var parsedLockFileVersion uvLockFileVersion

	// we cannot use the reader twice, so we read the contents first --uv.lock files tend to be small enough
	contents, err := io.ReadAll(reader) //nolint:gocritic // multi-pass parse requires []byte
	if err != nil {
		return nil, nil, unknown.New(reader.Location, fmt.Errorf("failed to read uv lock file: %w", err))
	}

	_, err = toml.NewDecoder(bytes.NewReader(contents)).Decode(&parsedLockFileVersion)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read uv lock version: %w", err)
	}

	// We will need to add some logic to parse and branch on different
	// lock file versions should they arise, but this gets us
	// started down this road for now.
	if parsedLockFileVersion.Version > 1 {
		return nil, nil, fmt.Errorf("could not parse uv lock file version %d", parsedLockFileVersion.Version)
	}

	var parsedLockFile uvLockFile
	_, err = toml.NewDecoder(bytes.NewReader(contents)).Decode(&parsedLockFile)

	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse uv lock packages: %w", err)
	}

	var pkgs []pkg.Package
	specs := make(map[artifact.ID]dependency.Specification)
	for _, p := range parsedLockFile.Packages {
		np := newPackageForIndexWithMetadata(
			ctx,
			ulp.licenseResolver,
			p.Name,
			p.Version,
			newPythonUvLockEntry(p),
			reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		)
		pkgs = append(pkgs, np)
		specs[np.ID()] = uvLockDependencySpecification(p)
	}

	return pkgs, specs, unknown.IfEmptyf(pkgs, "unable to determine packages")
}

func isDependencyForUvExtra(dep uvDependency) bool {
	return strings.Contains(dep.Markers, "extra ==")
}

// uvLockDependencySpecification is built from the raw lock entry rather than the package metadata. When a lock
// holds several versions of one name (a forked resolution), uv records which version each dependency entry means,
// and that is the only way to pair a dependent with the right one. The pairing is carried by the resulting
// relationships, so the version does not need to live on the metadata.
func uvLockDependencySpecification(p uvPackage) dependency.Specification {
	var requires []string
	for _, dep := range p.Dependencies {
		if isDependencyForUvExtra(dep) {
			continue
		}
		requires = append(requires, uvLockRequires(dep)...)
	}

	var variants []dependency.ProvidesRequires
	for _, extra := range slices.Sorted(maps.Keys(p.OptionalDependencies)) {
		var extraRequires []string
		for _, dep := range p.OptionalDependencies[extra] {
			extraRequires = append(extraRequires, uvLockRequires(dep)...)
		}
		variants = append(variants,
			dependency.ProvidesRequires{
				Provides: uvLockProvides(p, extra),
				Requires: extraRequires,
			},
		)
	}

	return dependency.Specification{
		ProvidesRequires: dependency.ProvidesRequires{
			Provides: uvLockProvides(p, ""),
			Requires: requires,
		},
		Variants: variants,
	}
}

// uvLockProvides offers both the bare ref (for dependency entries without a version) and the versioned ref (for
// dependency entries uv pinned to this version).
func uvLockProvides(p uvPackage, extra string) []string {
	return []string{packageRef(p.Name, extra), uvLockPackageRef(p.Name, p.Version, extra)}
}

// uvLockRequires always requires the base package, plus each extra individually (name[extra1] and name[extra2],
// never name[extra1,extra2]).
func uvLockRequires(dep uvDependency) []string {
	refs := []string{uvLockPackageRef(dep.Name, dep.Version, "")}
	for _, extra := range dep.Extras {
		refs = append(refs, uvLockPackageRef(dep.Name, dep.Version, extra))
	}
	return refs
}

func uvLockPackageRef(name, version, extra string) string {
	ref := packageRef(name, extra)
	version = strings.TrimSpace(version)
	if version == "" {
		return ref
	}
	return ref + "@" + version
}
