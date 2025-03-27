package python

import (
	"context"
	"fmt"

	"github.com/BurntSushi/toml"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
)

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
	Name   string   `toml:"name"`
	Extras []string `toml:"extra"`
}

type Distribution struct {
	Url  string `toml:"url"`
	Hash string `toml:"hash"`
	Size int    `toml:"size"`
}

type RequiresDist []struct {
	Name      string   `toml:"name"`
	Marker    string   `toml:"marker"`
	Extras    []string `toml:"extras"`
	Specifier string   `toml:"specifier"`
}

type Metadata struct {
	RequiresDist   RequiresDist `toml:"requires-dist"`
	ProvidesExtras []string     `toml:"provides-extras"`
}

// parseUvLock is a parser function for uv.lock contents, returning all the pakcages discovered
func parseUvLock(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	pkgs, dependency, err := uvLockPackages(reader)
	if err != nil {
		return nil, nil, err
	}

	return pkgs, dependency, err
}

func uvLockPackages(reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var parsedLockFile UvLockFile
	_, err := toml.NewDecoder(reader).Decode(&parsedLockFile)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to read uv lock packages: %w", err)
	}

	// We will need to add some logic to parse and branch on different
	// lock file versions should they arise, but this gets us
	// started down this road for now.
	if parsedLockFile.Version > 1 {
		return nil, nil, fmt.Errorf("Could not parse UV Lock file version %d:", parsedLockFile.Version)
	}

	var pkgs []pkg.Package
	for _, p := range parsedLockFile.Packages {
		pkgs = append(
			pkgs,
			newPackageForIndexWithMetadata(
				p.Name,
				p.Version,
				p,
				reader.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
			),
		)
	}

	return pkgs, dependency.Resolve(uvLockDependencySpecifier, pkgs), unknown.IfEmptyf(pkgs, "unable to determine packages")
}

func uvLockDependencySpecifier(p pkg.Package) dependency.Specification {
	meta, ok := p.Metadata.(Package)
	if !ok {
		log.Tracef("cataloger failed to extract UV lock metadata for package %+v", p.Name)
		return dependency.Specification{}
	}

	provides := []string{packageRef(p.Name, "")}

	var requires []string
	//add required deps (not extras)
	for _, dep := range meta.Dependencies {
		requires = append(requires, packageRef(dep.Name, ""))
		for _, extra := range dep.Extras {
			requires = append(requires, packageRef(dep.Name, extra))
		}

	}

	var variants []dependency.ProvidesRequires
	for extra_key, extra_dep := range meta.OptionalDependencies {
		var extra_deps []string

		for _, x := range extra_dep {
			extra_deps = append(extra_deps, x.Name)
		}

		variants = append(variants,
			dependency.ProvidesRequires{
				Provides: []string{packageRef(p.Name, extra_key)},
				Requires: extractPackageNames(extra_deps),
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
