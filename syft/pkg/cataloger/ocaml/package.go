package ocaml

import (
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func newOpamPackage(m pkg.OpamPackage, fileLocation file.Location) pkg.Package {
	p := pkg.Package{
		Name:      m.Name,
		Version:   m.Version,
		Licenses:  pkg.NewLicenseSet(pkg.NewLicensesFromLocation(fileLocation, m.Licenses...)...),
		PURL:      opamPackageURL(m.Name, m.Version),
		Locations: file.NewLocationSet(fileLocation),
		Type:      pkg.OpamPkg,
		Language:  pkg.OCaml,
		// no attempt is made by the parser function to raise up dependency relationships
		Dependencies: pkg.IncompleteDependencies,
		Metadata:     m,
	}

	p.SetID()

	return p
}

func opamPackageURL(name, version string) string {
	var qualifiers packageurl.Qualifiers

	return packageurl.NewPackageURL(
		"opam",
		"",
		name,
		version,
		qualifiers,
		"",
	).ToString()
}
