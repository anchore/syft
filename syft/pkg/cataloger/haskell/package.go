package haskell

import (
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func newPackage(name, version string, m *pkg.HackageMetadata, locations ...file.Location) pkg.Package {
	p := pkg.Package{
		Name:      name,
		Version:   version,
		Locations: file.NewLocationSet(locations...),
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
