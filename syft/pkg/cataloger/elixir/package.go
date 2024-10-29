package elixir

import (
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func newPackage(d pkg.ElixirMixLockEntry, locations ...file.Location) pkg.Package {
	p := pkg.Package{
		Name:      d.Name,
		Version:   d.Version,
		Language:  pkg.Elixir,
		Locations: file.NewLocationSet(locations...),
		PURL:      packageURL(d),
		Type:      pkg.HexPkg,
		// we do not attempt to parse dependencies from the mix.lock file
		Dependencies: pkg.IncompleteDependencies,
		Metadata:     d,
	}

	p.SetID()

	return p
}

func packageURL(m pkg.ElixirMixLockEntry) string {
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
