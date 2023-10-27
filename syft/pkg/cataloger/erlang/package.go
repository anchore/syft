package erlang

import (
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func newPackage(d pkg.ErlangRebarLockEntry, locations ...file.Location) pkg.Package {
	p := pkg.Package{
		Name:      d.Name,
		Version:   d.Version,
		Language:  pkg.Erlang,
		Locations: file.NewLocationSet(locations...),
		PURL:      packageURL(d),
		Type:      pkg.HexPkg,
		Metadata:  d,
	}

	p.SetID()

	return p
}

func packageURL(m pkg.ErlangRebarLockEntry) string {
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
