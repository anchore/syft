package python

import (
	"context"
	"fmt"
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
type UvLockFileVersion struct {
	Version  int `toml:"version"`
	Revision int `toml:"revision"`
}

type UvLockFile struct {
	Version        int       `toml:"version"`
	Revision       int       `toml:"revision"`
	RequiresPython string    `toml:"requires-python"`
	Packages       []Package `toml:"package"`
}

type Package struct {
	Name                 string                  `toml:"name"`
	Version              string                  `toml:"version"`
	Source               map[string]string       `toml:"source"` // Possible key values for Source are: registry, git, direct, path, directory, editable, virtual
	Dependencies         Dependencies            `toml:"dependencies"`
	DevDependencies      map[string]Dependencies `toml:"dev-dependencies"`
	OptionalDependencies map[string]Dependencies `toml:"optional-dependencies"`
	Sdist                Distribution            `toml:"sdist"`
	Wheels               []Distribution          `toml:"wheels"`
	Metadata             Metadata                `toml:"metadata"`
}

type Dependencies []struct {
	Name    string   `toml:"name"`
	Extras  []string `toml:"extra"`
	Markers string   `toml:"marker"`
}

type Distribution struct {
	Url  string `toml:"url"`
	Hash string `toml:"hash"`
	Size int    `toml:"size"`
}

type RequiresDist []struct {
	Name      string   `toml:"name"`
	Markers   string   `toml:"marker"`
	Extras    []string `toml:"extras"`
	Specifier string   `toml:"specifier"`
}

type Metadata struct {
	RequiresDist   RequiresDist `toml:"requires-dist"`
	ProvidesExtras []string     `toml:"provides-extras"`
}

// parseUvLock is a parser function for uv.lock contents, returning all the pakcages discovered
func parseUvLock(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	pkgs, err := uvLockPackages(reader)
	if err != nil {
		return nil, nil, err
	}

	return pkgs, dependency.Resolve(uvLockDependencySpecifier, pkgs), err
}

type PythonUvLockDependencyEntry struct {
	Name     string   `json:"name"`
	Version  string   `json:"version"`
	Optional bool     `json:"optional"`
	Markers  string   `json:"markers,omitempty"`
	Extras   []string `json:"extras,omitempty"`
}

type PythonUvLockExtraEntry struct {
	Name         string   `json:"name"`
	Dependencies []string `json:"dependencies"`
}

type PythonUvLockEntry struct {
	Index        string                        `mapstructure:"index" json:"index"`
	Dependencies []PythonUvLockDependencyEntry `json:"dependencies"`
	Extras       []PythonUvLockExtraEntry      `json:"extras,omitempty"`
}

func extractUvIndex(p Package) string {
	// This is a map, but there should only be one key, value pair
	var rvalue string
	for _, value := range p.Source {
		rvalue = value
	}

	return rvalue
}

func extractUvDependencies(p Package, pkgVerMap map[string]string) []PythonUvLockDependencyEntry {
	var deps []PythonUvLockDependencyEntry
	for _, d := range p.Dependencies {
		deps = append(deps, PythonUvLockDependencyEntry{
			Name:    d.Name,
			Extras:  d.Extras,
			Markers: d.Markers,
			Version: pkgVerMap[d.Name],
		})
	}
	sort.Slice(deps, func(i, j int) bool {
		return deps[i].Name < deps[j].Name
	})
	return deps
}

func extractUvExtras(p Package) []PythonUvLockExtraEntry {
	var extras []PythonUvLockExtraEntry
	for name, deps_struct := range p.OptionalDependencies {
		var extra_deps []string
		for _, deps := range deps_struct {
			extra_deps = append(extra_deps, deps.Name)
		}
		extras = append(extras, PythonUvLockExtraEntry{
			Name:         name,
			Dependencies: extra_deps,
		})
	}
	return extras
}

func newPythonUvLockEntry(p Package, pkgVerMap map[string]string) PythonUvLockEntry {
	return PythonUvLockEntry{
		Index:        extractUvIndex(p),
		Dependencies: extractUvDependencies(p, pkgVerMap),
		Extras:       extractUvExtras(p),
	}
}

func uvLockPackages(reader file.LocationReadCloser) ([]pkg.Package, error) {
	var parsedLockFileVersion UvLockFileVersion
	var parsedLockFile UvLockFile

	_, err := toml.NewDecoder(reader).Decode(&parsedLockFileVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to read uv lock version: %w", err)
	}

	// We will need to add some logic to parse and branch on different
	// lock file versions should they arise, but this gets us
	// started down this road for now.
	if parsedLockFileVersion.Version > 1 {
		return nil, fmt.Errorf("could not parse UV Lock file version %d:", parsedLockFile.Version)
	}

	_, err = toml.NewDecoder(reader).Decode(&parsedLockFile)

	if err != nil {
		return nil, fmt.Errorf("failed to parse uv lock packages: %w", err)
	}

	// The uv lock file doesn't store the dependency version in the dependency structure.
	// Thus, we need a name -> version map for invoking extractUvDependencies.
	// We then, of course, have to pass it down the call stack.
	var pkgVerMap map[string]string
	pkgVerMap = make(map[string]string)
	for _, p := range parsedLockFile.Packages {
		pkgVerMap[p.Name] = p.Version
	}

	var pkgs []pkg.Package
	for _, p := range parsedLockFile.Packages {
		pkgs = append(pkgs,
			newPackageForIndexWithMetadata(
				p.Name,
				p.Version,
				newPythonUvLockEntry(p, pkgVerMap),
				reader.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
			),
		)
	}

	return pkgs, unknown.IfEmptyf(pkgs, "unable to determine packages")
}

func isDependencyForUvExtra(dep PythonUvLockDependencyEntry) bool {
	return strings.Contains(dep.Markers, "extra ==")
}

// This is identical to poetryLockDependencySpecifier since it operates on identical
// data structurs. Keeping it separate for now since it's always possible for data
// structures to change down the line.
// It *is* possible we may be able to merge the Uv and Poetry data structures
func uvLockDependencySpecifier(p pkg.Package) dependency.Specification {
	meta, ok := p.Metadata.(PythonUvLockEntry)
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
