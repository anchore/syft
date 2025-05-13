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

func newPackageFromOTP(name, version string, locations ...file.Location) pkg.Package {
	p := pkg.Package{
		Name:      name,
		Version:   version,
		Language:  pkg.Erlang,
		Locations: file.NewLocationSet(locations...),
		PURL:      packageURLFromOTP(name, version),
		Type:      pkg.ErlangOTPPkg,
	}

	p.SetID()

	return p
}

func packageURLFromOTP(name, version string) string {
	var qualifiers packageurl.Qualifiers

	return packageurl.NewPackageURL(
		packageurl.TypeOTP,
		"",
		name,
		version,
		qualifiers,
		"",
	).ToString()
}
