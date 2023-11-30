package erlang

import (
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func newPackageFromRebar(d pkg.ErlangRebarLockEntry, locations ...file.Location) pkg.Package {
	p := pkg.Package{
		Name:      d.Name,
		Version:   d.Version,
		Language:  pkg.Erlang,
		Locations: file.NewLocationSet(locations...),
		PURL:      packageURLFromRebar(d),
		Type:      pkg.HexPkg,
		Metadata:  d,
	}

	p.SetID()

	return p
}

func packageURLFromRebar(m pkg.ErlangRebarLockEntry) string {
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

func newPackageFromOTP(d pkg.ErlangOTPApplication, locations ...file.Location) pkg.Package {
	p := pkg.Package{
		Name:      d.Name,
		Version:   d.Version,
		Language:  pkg.Erlang,
		Locations: file.NewLocationSet(locations...),
		PURL:      packageURLFromOTP(d),
		Type:      pkg.UnknownPkg,
		Metadata:  d,
	}

	p.SetID()

	return p
}

func packageURLFromOTP(m pkg.ErlangOTPApplication) string {
	var qualifiers packageurl.Qualifiers

	return packageurl.NewPackageURL(
		packageurl.TypeGeneric,
		"",
		m.Name,
		m.Version,
		qualifiers,
		"",
	).ToString()
}
