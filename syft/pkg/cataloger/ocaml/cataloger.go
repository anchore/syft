/*
Package ocaml provides a concrete Cataloger implementation for packages relating to the OCaml language ecosystem.
*/
package ocaml

import (
	"path"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
)

// NewOpamPackageManagerCataloger returns a new cataloger object for declared OCaml opam packages: package
// definitions (`<name>.opam` and `opam` files) and lock files (`<name>.opam.locked`).
func NewOpamPackageManagerCataloger() pkg.Cataloger {
	return generic.NewCataloger("opam-cataloger").
		WithParserByGlobs(parseOpamPackage, "**/*.opam", "**/opam").
		WithParserByGlobs(parseOpamLockFile, "**/*.opam.locked")
}

// NewInstalledLibraryCataloger returns a new cataloger object for OCaml libraries installed outside of an opam
// switch (e.g. by a system package manager), identified by their dune-package or findlib META files.
func NewInstalledLibraryCataloger() pkg.Cataloger {
	return generic.NewCataloger("ocaml-installed-library-cataloger").
		WithParserByGlobs(parseDunePackage, "**/dune-package").
		WithParserByGlobs(parseFindlibMeta, "**/META").
		WithProcessors(resolveWithinLibraryDirs)
}

// resolveWithinLibraryDirs resolves dependencies between the libraries installed in the same library directory
// (e.g. /usr/lib/ocaml), so that libraries of separate installations are never linked.
func resolveWithinLibraryDirs(pkgs []pkg.Package, rels []artifact.Relationship, err error) ([]pkg.Package, []artifact.Relationship, error) {
	var dirs []string
	byDir := map[string][]pkg.Package{}
	for _, p := range pkgs {
		dir := libraryDir(p)
		if _, ok := byDir[dir]; !ok {
			dirs = append(dirs, dir)
		}
		byDir[dir] = append(byDir[dir], p)
	}
	for _, dir := range dirs {
		rels = append(rels, dependency.Resolve(opamDependencySpecifier, byDir[dir])...)
	}
	return pkgs, rels, err
}

// libraryDir returns the directory holding the library's own directory (`<lib>` for `<lib>/<name>/META`), from the
// primary evidence of the package.
func libraryDir(p pkg.Package) string {
	locs := p.Locations.ToSlice()
	if len(locs) == 0 {
		return ""
	}
	return path.Dir(path.Dir(locs[0].RealPath))
}

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
