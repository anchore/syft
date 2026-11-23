package ocaml

import (
	"context"
	"path"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
)

// hasUsableLockFile reports whether the lock file exists and can be read as an opam file. When it cannot, the lock
// file gives no package, so the declared opam file stays the only description of the project.
func hasUsableLockFile(resolver file.Resolver, lockPath string) bool {
	_, _, ok := readSiblingOpamFields(resolver, lockPath)
	return ok
}

// parseOpamLockFile parses a `<name>.opam.locked` file (as written by `opam lock`). The project package takes its
// descriptive metadata (license, homepage, ...) from the sibling `<name>.opam` file when present. Relationships are
// resolved within the lock file only, so that packages of other projects or lock files are never linked.
func parseOpamLockFile(ctx context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	p := reader.Path()
	if skipDeclaredOpamFile(resolver, p) {
		return nil, nil, nil
	}
	fields, ok := readOpamFields(reader)
	if !ok {
		return nil, nil, nil
	}
	name := strings.TrimSuffix(path.Base(p), opamLockFileSuffix)

	meta := opamMetadata(name, fields.Version, fields)
	licenseLocation := reader.Location
	if project, loc, found := readSiblingOpamFields(resolver, strings.TrimSuffix(p, ".locked")); found {
		if meta.Version == "" {
			meta.Version = project.Version
		}
		meta.Licenses = project.Licenses
		meta.Homepage = project.Homepage
		meta.URL = project.URL
		meta.Checksums = project.Checksums
		licenseLocation = loc
	}

	root := withLicenseLocation(ctx, newOpamPackage(ctx, meta, reader.Location), meta.Licenses, licenseLocation)

	pkgs := append([]pkg.Package{root}, pinnedDependencyPackages(ctx, name, fields, reader.Location)...)
	return pkgs, dependency.Resolve(opamDependencySpecifier, pkgs), nil
}

// pinnedDependencyPackages returns a package for each dependency a lock file pins to a version. Pins that are only
// needed to test, document or develop the project are left out, as dev dependencies are for other ecosystems.
func pinnedDependencyPackages(ctx context.Context, self string, fields opamFields, location file.Location) []pkg.Package {
	var pkgs []pkg.Package
	seen := map[string]bool{self: true}
	for _, d := range fields.Depends {
		if d.Version == "" || d.Development || seen[d.Name] {
			continue
		}
		seen[d.Name] = true
		pkgs = append(pkgs, newOpamPackage(ctx, pkg.OpamPackage{Name: d.Name, Version: d.Version}, location))
	}
	return pkgs
}
