package python

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/anchore/syft/internal/log"
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

type uvDependencies []struct {
	Name    string   `toml:"name"`
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
	pkgs, err := ulp.uvLockPackages(ctx, reader)
	if err != nil {
		return nil, nil, err
	}

	return pkgs, dependency.Resolve(uvLockDependencySpecifier, pkgs), err
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

func (ulp uvLockParser) uvLockPackages(ctx context.Context, reader file.LocationReadCloser) ([]pkg.Package, error) {
	var parsedLockFileVersion uvLockFileVersion

	// we cannot use the reader twice, so we read the contents first --uv.lock files tend to be small enough
	contents, err := io.ReadAll(reader)
	if err != nil {
		return nil, unknown.New(reader.Location, fmt.Errorf("failed to read uv lock file: %w", err))
	}

	_, err = toml.NewDecoder(bytes.NewReader(contents)).Decode(&parsedLockFileVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to read uv lock version: %w", err)
	}

	// We will need to add some logic to parse and branch on different
	// lock file versions should they arise, but this gets us
	// started down this road for now.
	if parsedLockFileVersion.Version > 1 {
		return nil, fmt.Errorf("could not parse uv lock file version %d", parsedLockFileVersion.Version)
	}

	var parsedLockFile uvLockFile
	_, err = toml.NewDecoder(bytes.NewReader(contents)).Decode(&parsedLockFile)

	if err != nil {
		return nil, fmt.Errorf("failed to parse uv lock packages: %w", err)
	}

	// The uv lock file doesn't store the dependency version in the dependency structure.
	// Thus, we need a name -> version map for invoking extractUvDependencies.
	// We then, of course, have to pass it down the call stack.
	var pkgVerMap = make(map[string]string)
	for _, p := range parsedLockFile.Packages {
		pkgVerMap[p.Name] = p.Version
	}

	var pkgs []pkg.Package
	for _, p := range parsedLockFile.Packages {
		pkgs = append(pkgs,
			newPackageForIndexWithMetadata(
				ctx,
				ulp.licenseResolver,
				p.Name,
				p.Version,
				newPythonUvLockEntry(p),
				reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
			),
		)
	}

	return pkgs, unknown.IfEmptyf(pkgs, "unable to determine packages")
}

func isDependencyForUvExtra(dep pkg.PythonUvLockDependencyEntry) bool {
	return strings.Contains(dep.Markers, "extra ==")
}

// This is identical to poetryLockDependencySpecifier since it operates on identical
// data structures. Keeping it separate for now since it's always possible for data
// structures to change down the line.
// It *is* possible we may be able to merge the Uv and Poetry data structures
func uvLockDependencySpecifier(p pkg.Package) dependency.Specification { //nolint:dupl // this is very similar to the poetry lock dependency specifier, but should remain separate
	meta, ok := p.Metadata.(pkg.PythonUvLockEntry)
	if !ok {
		log.Tracef("cataloger failed to extract UV lock metadata for package %+v", p.Name)
		return dependency.Specification{}
	}

	provides := []string{packageRef(p.Name, "")}

	var requires []string

	for _, dep := range meta.Dependencies {
		if isDependencyForUvExtra(dep) {
			continue
		}

		requires = append(requires, packageRef(dep.Name, ""))

		for _, extra := range dep.Extras {
			requires = append(requires, packageRef(dep.Name, extra))
		}
	}

	var variants []dependency.ProvidesRequires
	for _, extra := range meta.Extras {
		variants = append(variants,
			dependency.ProvidesRequires{
				Provides: []string{packageRef(p.Name, extra.Name)},
				Requires: extractPackageNames(extra.Dependencies),
			},
		)
	}

	return dependency.Specification{
		ProvidesRequires: dependency.ProvidesRequires{
			Provides: provides,
			Requires: requires,
		},
		Variants: variants,
	}
}
