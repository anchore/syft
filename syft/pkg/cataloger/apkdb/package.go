package apkdb

import (
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func newPackage(d parsedData, release *linux.Release, dbLocation source.Location) pkg.Package {
	licenseStrings := strings.Split(d.License, " ")

	p := pkg.Package{
		Name:         d.Package,
		Version:      d.Version,
		Locations:    source.NewLocationSet(dbLocation.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
		Licenses:     pkg.NewLicensesFromLocation(dbLocation, licenseStrings...),
		PURL:         packageURL(d, release),
		Type:         pkg.ApkPkg,
		MetadataType: pkg.ApkMetadataType,
		Metadata:     d.ApkMetadata,
	}

	p.SetID()

	return p
}

// packageURL returns the PURL for the specific Alpine package (see https://github.com/package-url/purl-spec)
func packageURL(m parsedData, distro *linux.Release) string {
	if distro == nil {
		return ""
	}

	qualifiers := map[string]string{
		pkg.PURLQualifierArch: m.Architecture,
	}

	if m.OriginPackage != m.Package {
		qualifiers[pkg.PURLQualifierUpstream] = m.OriginPackage
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
