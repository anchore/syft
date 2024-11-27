package rust

import (
	"context"
	"fmt"

	"github.com/pelletier/go-toml"

	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
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
	pkgIndex := make(map[string]int)

	for _, p := range m.Packages {
		if p.Dependencies == nil {
			p.Dependencies = make([]string, 0)
		}
		newPkg := newPackageFromCargoMetadata(
			p,
			reader.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		)
		pkgs = append(
			pkgs,
			newPkg,
		)
		newIx := len(pkgs) - 1
		// Cargo.lock dependencies are strings that are the name of a package, if that
		// is unambiguous, or a string like "name version" if the name alone is not
		// ambiguous. Set both keys in the map, since we don't know which key is
		// going to be used until we're trying to resolve dependencies. If the
		// first key is overwritten, that means the package name was an ambiguous dependency
		// and "name version" will be used as the key anyway.
		keys := []string{
			newPkg.Name,
			fmt.Sprintf("%s %s", newPkg.Name, newPkg.Version),
		}
		for _, k := range keys {
			pkgIndex[k] = newIx
		}
	}
	var relationships []artifact.Relationship
	for _, p := range pkgs {
		meta := p.Metadata.(pkg.RustCargoLockEntry)
		for _, d := range meta.Dependencies {
			i, ok := pkgIndex[d]
			if !ok {
				continue
			}
			relationships = append(relationships, artifact.Relationship{
				From: p,
				To:   pkgs[i],
				Type: artifact.DependencyOfRelationship,
			})
		}
	}

	return pkgs, relationships, unknown.IfEmptyf(pkgs, "unable to determine packages")
}
