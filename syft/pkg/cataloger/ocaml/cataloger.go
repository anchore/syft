/*
Package ocaml provides a concrete Cataloger implementation for packages relating to the OCaml language ecosystem.
*/
package ocaml

import (
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
)

// NewOpamPackageManagerCataloger returns a new cataloger object for declared OCaml opam packages: package
// definitions (`<name>.opam` and `opam` files) and lock files (`<name>.opam.locked`).
func NewOpamPackageManagerCataloger() pkg.Cataloger {
	return generic.NewCataloger("opam-cataloger").
		WithParserByGlobs(parseOpamPackage, "**/*.opam", "**/opam").
		WithParserByGlobs(parseOpamLockFile, "**/*.opam.locked").
		WithProcessors(dependency.Processor(opamDependencySpecifier))
}

// NewOpamSwitchCataloger returns a new cataloger object for OCaml packages installed in an opam switch.
func NewOpamSwitchCataloger() pkg.Cataloger {
	return generic.NewCataloger("opam-switch-cataloger").
		WithParserByGlobs(parseOpamSwitchPackage, "**/.opam-switch/packages/*/opam").
		WithProcessors(dependency.Processor(opamDependencySpecifier))
}

// NewInstalledLibraryCataloger returns a new cataloger object for OCaml libraries installed outside of an opam
// switch (e.g. by a system package manager), identified by their dune-package or findlib META files.
func NewInstalledLibraryCataloger() pkg.Cataloger {
	return generic.NewCataloger("ocaml-installed-library-cataloger").
		WithParserByGlobs(parseDunePackage, "**/dune-package").
		WithParserByGlobs(parseFindlibMeta, "**/META").
		WithProcessors(dependency.Processor(opamDependencySpecifier))
}

var _ dependency.Specifier = opamDependencySpecifier

// opamDependencySpecifier declares that an opam package provides its own name and requires the packages named in
// its depends field, so the dependency processor can resolve dependency-of relationships between them.
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
