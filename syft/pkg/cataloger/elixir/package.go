package elixir

import (
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func newPackage(d pkg.MixLockMetadata, locations ...file.Location) pkg.Package {
	p := pkg.Package{
		Name:         d.Name,
		Version:      d.Version,
		Language:     pkg.Elixir,
		Locations:    file.NewLocationSet(locations...),
		PURL:         packageURL(d),
		Type:         pkg.HexPkg,
		MetadataType: pkg.MixLockMetadataType,
		Metadata:     d,
	}

	p.SetID()

	return p
}

func packageURL(m pkg.MixLockMetadata) string {
	var qualifiers packageurl.Qualifiers

	return packageurl.NewPackageURL(
		packageurl.TypeHex,
		"",
		m.Name,
		m.Version,
		qualifiers,
		"",
	).ToString()
}
