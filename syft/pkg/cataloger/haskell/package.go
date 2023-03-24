package haskell

import (
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func newPackage(name, version string, m *pkg.HackageMetadata, locations ...source.Location) pkg.Package {
	p := pkg.Package{
		Name:      name,
		Version:   version,
		Locations: source.NewLocationSet(locations...),
		PURL:      packageURL(name, version),
		Language:  pkg.Haskell,
		Type:      pkg.HackagePkg,
	}

	if m != nil {
		p.MetadataType = pkg.HackageMetadataType
		p.Metadata = *m
	}

	p.SetID()

	return p
}

func packageURL(name, version string) string {
	var qualifiers packageurl.Qualifiers

	return packageurl.NewPackageURL(
		packageurl.TypeHackage,
		"",
		name,
		version,
		qualifiers,
		"",
	).ToString()
}
