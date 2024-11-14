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
		keys := []string{
			newPkg.Name,
			fmt.Sprintf("%s %s", newPkg.Name, newPkg.Version),
			fmt.Sprintf("%s %s", newPkg.Name, newPkg.Metadata.(pkg.RustCargoLockEntry).Source),
			fmt.Sprintf("%s %s %s", newPkg.Name, newPkg.Version, newPkg.Metadata.(pkg.RustCargoLockEntry).Source),
		}
		for _, k := range keys {
			pkgIndex[k] = newIx
		}
	}
	var relationships []artifact.Relationship
	for _, p := range pkgs {
		meta := p.Metadata.(pkg.RustCargoLockEntry)
		for _, d := range meta.Dependencies {
			relationships = append(relationships, artifact.Relationship{
				From: p,
				To:   pkgs[pkgIndex[d]],
				Type: artifact.DependencyOfRelationship,
			})
		}
	}

	return pkgs, relationships, unknown.IfEmptyf(pkgs, "unable to determine packages")
}
