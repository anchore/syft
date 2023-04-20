package swift

import (
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func newPackage(name, version, hash string, locations ...file.Location) pkg.Package {
	p := pkg.Package{
		Name:         name,
		Version:      version,
		PURL:         packageURL(name, version),
		Locations:    file.NewLocationSet(locations...),
		Type:         pkg.CocoapodsPkg,
		Language:     pkg.Swift,
		MetadataType: pkg.CocoapodsMetadataType,
		Metadata: pkg.CocoapodsMetadata{
			Checksum: hash,
		},
	}

	p.SetID()

	return p
}

func packageURL(name, version string) string {
	var qualifiers packageurl.Qualifiers

	return packageurl.NewPackageURL(
		packageurl.TypeCocoapods,
		"",
		name,
		version,
		qualifiers,
		"",
	).ToString()
}
