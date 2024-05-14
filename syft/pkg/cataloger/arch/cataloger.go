/*
Package arch provides a concrete Cataloger implementations for packages relating to the Arch linux distribution.
*/
package arch

import (
	"context"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

type cataloger struct {
	*generic.Cataloger
}

// NewDBCataloger returns a new cataloger object initialized for arch linux pacman database flat-file stores.
func NewDBCataloger() pkg.Cataloger {
	return cataloger{
		Cataloger: generic.NewCataloger("alpm-db-cataloger").
			WithParserByGlobs(parseAlpmDB, pkg.AlpmDBGlob),
	}
}

func (c cataloger) Catalog(ctx context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	pkgs, rels, err := c.Cataloger.Catalog(ctx, resolver)
	if err != nil {
		return nil, nil, err
	}

	rels = append(rels, associateRelationships(pkgs)...)

	return pkgs, rels, nil
}

// associateRelationships will create relationships between packages based on the "Depends" and "Provides"
// fields for installed packages. If there is an installed package that has a dependency that is (somehow) not installed,
// then that relationship (between the installed and uninstalled package) will NOT be created.
func associateRelationships(pkgs []pkg.Package) (relationships []artifact.Relationship) {
	// map["provides" + "package"] -> packages that provide that package
	lookup := make(map[string][]pkg.Package)

	// read providers and add lookup keys as needed
	for _, p := range pkgs {
		meta, ok := p.Metadata.(pkg.AlpmDBEntry)
		if !ok {
			log.Warnf("cataloger failed to extract alpm 'provides' metadata for package %+v", p.Name)
			continue
		}
		// allow for lookup by package name
		lookup[p.Name] = append(lookup[p.Name], p)

		for _, provides := range meta.Provides {
			// allow for lookup by exact specification
			lookup[provides] = append(lookup[provides], p)

			// allow for lookup by library name only
			k := stripVersionSpecifier(provides)
			lookup[k] = append(lookup[k], p)
		}
	}

	// read "Depends" and match with provider keys
	for _, p := range pkgs {
		meta, ok := p.Metadata.(pkg.AlpmDBEntry)
		if !ok {
			log.Warnf("cataloger failed to extract alpm 'dependency' metadata for package %+v", p.Name)
			continue
		}

		for _, dep := range meta.Depends {
			for _, depPkg := range lookup[dep] {
				relationships = append(relationships, artifact.Relationship{
					From: depPkg,
					To:   p,
					Type: artifact.DependencyOfRelationship,
				})
			}
		}
	}
	return relationships
}

func stripVersionSpecifier(s string) string {
	// examples:
	// gcc-libs                  -->  gcc-libs
	// libtree-sitter.so=0-64    -->  libtree-sitter.so

	items := strings.Split(s, "=")
	if len(items) == 0 {
		return s
	}

	return strings.TrimSpace(items[0])
}
