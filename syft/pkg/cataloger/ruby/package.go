package ruby

import (
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func newGemfileLockPackage(name, version string, locations ...file.Location) pkg.Package {
	p := pkg.Package{
		Name:      name,
		Version:   version,
		PURL:      packageURL(name, version),
		Locations: file.NewLocationSet(locations...),
		Language:  pkg.Ruby,
		Type:      pkg.GemPkg,
	}

	p.SetID()

	return p
}

func newGemspecPackage(m pkg.GemMetadata, locations ...file.Location) pkg.Package {
	p := pkg.Package{
		Name:         m.Name,
		Version:      m.Version,
		Locations:    file.NewLocationSet(locations...),
		PURL:         packageURL(m.Name, m.Version),
		Licenses:     m.Licenses,
		Language:     pkg.Ruby,
		Type:         pkg.GemPkg,
		MetadataType: pkg.GemMetadataType,
		Metadata:     m,
	}

	p.SetID()

	return p
}

func packageURL(name, version string) string {
	var qualifiers packageurl.Qualifiers

	return packageurl.NewPackageURL(
		packageurl.TypeGem,
		"",
		name,
		version,
		qualifiers,
		"",
	).ToString()
}
