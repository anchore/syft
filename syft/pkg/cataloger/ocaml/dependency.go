package ocaml

import (
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
)

var _ dependency.Specifier = opamDependencySpecifier

// opamDependencySpecifier declares that an opam package provides its own name and requires the packages named in
// its depends field, so that dependency-of relationships can be resolved between packages of the same lock file.
func opamDependencySpecifier(p pkg.Package) dependency.Specification {
	meta, ok := p.Metadata.(pkg.OpamPackage)
	if !ok {
		log.Tracef("cataloger failed to extract opam metadata for package %+v", p.Name)
		return dependency.Specification{}
	}
	return dependency.Specification{
		ProvidesRequires: dependency.ProvidesRequires{
			Provides: []string{p.Name},
			Requires: meta.Dependencies,
		},
	}
}
