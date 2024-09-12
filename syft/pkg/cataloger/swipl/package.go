package swipl

import (
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func newSwiplPackPackage(m pkg.SwiplPackEntry, locations ...file.Location) pkg.Package {
	p := pkg.Package{
		Name:      m.Name,
		Version:   m.Version,
		PURL:      swiplpackPackageURL(m.Name, m.Version),
		Locations: file.NewLocationSet(locations...),
		Type:      pkg.SwiplPackPkg,
		Language:  pkg.Swipl,
		Metadata:  m,
	}

	p.SetID()

	return p
}

func swiplpackPackageURL(name, version string) string {
	var qualifiers packageurl.Qualifiers

	return packageurl.NewPackageURL(
		"swiplpack",
		"",
		name,
		version,
		qualifiers,
		"",
	).ToString()
}
