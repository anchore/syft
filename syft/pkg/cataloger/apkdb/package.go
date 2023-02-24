package apkdb

import (
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func newPackage(d pkg.ApkMetadata, release *linux.Release, locations ...source.Location) pkg.Package {
	p := pkg.Package{
		Name:         d.Package,
		Version:      d.Version,
		Locations:    source.NewLocationSet(locations...),
		Licenses:     strings.Split(d.License, " "),
		PURL:         packageURL(d, release),
		Type:         pkg.ApkPkg,
		MetadataType: pkg.ApkMetadataType,
		Metadata:     d,
	}

	p.SetID()

	return p
}

// packageURL returns the PURL for the specific Alpine package (see https://github.com/package-url/purl-spec)
func packageURL(m pkg.ApkMetadata, distro *linux.Release) string {
	if distro == nil {
		return ""
	}

	qualifiers := map[string]string{
		pkg.PURLQualifierArch: m.Architecture,
	}

	upstream := m.Upstream()
	if upstream != "" && upstream != m.Package {
		qualifiers[pkg.PURLQualifierUpstream] = upstream
	}

	return packageurl.NewPackageURL(
		packageurl.TypeAlpine,
		strings.ToLower(distro.ID),
		m.Package,
		m.Version,
		pkg.PURLQualifiers(
			qualifiers,
			distro,
		),
		"",
	).ToString()
}
