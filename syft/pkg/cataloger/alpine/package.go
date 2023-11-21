package alpine

import (
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/license"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
)

func newPackage(d parsedData, release *linux.Release, dbLocation file.Location) pkg.Package {
	// check if license is a valid spdx expression before splitting
	licenseStrings := []string{d.License}
	_, err := license.ParseExpression(d.License)
	if err != nil {
		// invalid so update to split on space
		licenseStrings = strings.Split(d.License, " ")
	}

	p := pkg.Package{
		Name:      d.Package,
		Version:   d.Version,
		Locations: file.NewLocationSet(dbLocation.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
		Licenses:  pkg.NewLicenseSet(pkg.NewLicensesFromLocation(dbLocation, licenseStrings...)...),
		PURL:      packageURL(d.ApkDBEntry, release),
		Type:      pkg.ApkPkg,
		Metadata:  d.ApkDBEntry,
	}

	p.SetID()

	return p
}

// packageURL returns the PURL for the specific Alpine package (see https://github.com/package-url/purl-spec)
func packageURL(m pkg.ApkDBEntry, distro *linux.Release) string {
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
