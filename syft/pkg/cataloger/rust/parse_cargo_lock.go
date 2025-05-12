package rust

import (
	"context"
	"fmt"
	"strings"

	"github.com/pelletier/go-toml"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
)

var _ generic.Parser = parseCargoLock

type cargoLockFile struct {
	Packages []pkg.RustCargoLockEntry `toml:"package"`
}

// parseCargoLock is a parser function for Cargo.lock contents, returning all rust cargo crates discovered.
func parseCargoLock(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	tree, err := toml.LoadReader(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to load Cargo.lock for parsing: %w", err)
	}

	m := cargoLockFile{}
	err = tree.Unmarshal(&m)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse Cargo.lock: %w", err)
	}

	var pkgs []pkg.Package

	for _, p := range m.Packages {
		if p.Dependencies == nil {
			p.Dependencies = make([]string, 0)
		}
		newPkg := newPackageFromCargoMetadata(
			p,
			reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		)
		pkgs = append(
			pkgs,
			newPkg,
		)
	}

	return pkgs, dependency.Resolve(dependencySpecification, pkgs), unknown.IfEmptyf(pkgs, "unable to determine packages")
}

func dependencySpecification(p pkg.Package) dependency.Specification {
	rustMeta, ok := p.Metadata.(pkg.RustCargoLockEntry)
	if !ok {
		log.Tracef("cataloger failed to extract rust Cargo.lock metadata for package %+v", p.Name)
		return dependency.Specification{}
	}

	// Cargo.lock dependencies are strings that are the name of a package, if that
	// is unambiguous, or a string like "name version" if the name alone is not
	// ambiguous, or strings like "name version (source)" if "name version" is ambiguous.
	// Provide all the strings, since we don't know which string will be used.
	// In other words, each package "provides" 3 entries, one for each name format,
	// and each package "requires" whatever it actually requires based on the Cargo.lock.
	provides := []string{
		p.Name,
		fmt.Sprintf("%s %s", p.Name, p.Version),
	}

	if rustMeta.Source != "" {
		src := rustMeta.Source
		if strings.HasPrefix(src, "git") && strings.Contains(src, "#") {
			src = strings.Split(src, "#")[0]
		}

		provides = append(provides, fmt.Sprintf("%s %s (%s)", p.Name, p.Version, src))
	}

	return dependency.Specification{
		ProvidesRequires: dependency.ProvidesRequires{
			Provides: provides,
			Requires: rustMeta.Dependencies,
		},
	}
}
