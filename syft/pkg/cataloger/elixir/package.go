package elixir

import (
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

// newPackage builds a package from a mix.lock entry. source is the entry's
// source atom (`hex`, `git`, or `path`). Only hex entries are backed by the
// hex.pm registry, so only they receive a pkg:hex/ PURL; git/path entries get
// an empty PURL to avoid being asserted as hex.pm packages (which would produce
// false hex.pm vulnerability matches).
func newPackage(source string, d pkg.ElixirMixLockEntry, locations ...file.Location) pkg.Package {
	p := pkg.Package{
		Name:      d.Name,
		Version:   d.Version,
		Language:  pkg.Elixir,
		Locations: file.NewLocationSet(locations...),
		PURL:      packageURL(source, d),
		Type:      pkg.HexPkg,
		Metadata:  d,
	}

	p.SetID()

	return p
}

func packageURL(source string, m pkg.ElixirMixLockEntry) string {
	// Non-hex sources (git, path) are not published to the hex.pm registry, so a
	// pkg:hex/ PURL would be incorrect and would drive false hex.pm vulnerability
	// matches. Emit no PURL for them.
	if source != "hex" {
		return ""
	}

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
