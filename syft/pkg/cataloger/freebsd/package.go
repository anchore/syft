package freebsd

import (
	"context"
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func newPackage(ctx context.Context, dbLocation file.Location, m pkg.FreeBSDPkgDBEntry) pkg.Package {
	p := pkg.Package{
		Name:      m.Name,
		Version:   m.Version,
		Locations: file.NewLocationSet(dbLocation.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
		Licenses:  pkg.NewLicenseSet(pkg.NewLicensesFromLocationWithContext(ctx, dbLocation, m.Licenses...)...),
		PURL:      packageURL(m),
		Type:      pkg.FreeBSDPkg,
		Metadata:  m,
	}

	p.SetID()
	return p
}

// packageURL returns the PURL for the FreeBSD package (there is no PURL type registered for FreeBSD pkgng
// packages at this time, so this is a reasonable custom type following the conventions of other custom types).
func packageURL(m pkg.FreeBSDPkgDBEntry) string {
	qualifiers := map[string]string{
		pkg.PURLQualifierArch: m.Arch,
		"origin":              m.Origin,
	}

	return packageurl.NewPackageURL(
		"freebsd",
		"",
		m.Name,
		m.Version,
		pkg.PURLQualifiers(qualifiers, nil),
		"",
	).ToString()
}

// stripDigestAlgoPrefix removes the pkgng hash algorithm prefix (e.g. "1$", where "1" denotes sha256) from a
// file checksum, leaving the raw hex digest.
func stripDigestAlgoPrefix(sum string) string {
	if _, digest, ok := strings.Cut(sum, "$"); ok {
		return digest
	}
	return sum
}

func newArchivePackage(ctx context.Context, archiveLocation file.Location, m pkg.FreeBSDPkgArchiveEntry) pkg.Package {
	p := pkg.Package{
		Name:      m.Name,
		Version:   m.Version,
		Locations: file.NewLocationSet(archiveLocation.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
		Licenses:  pkg.NewLicenseSet(pkg.NewLicensesFromLocationWithContext(ctx, archiveLocation, m.Licenses...)...),
		PURL:      archivePackageURL(m),
		Type:      pkg.FreeBSDPkg,
		Metadata:  m,
	}

	p.SetID()
	return p
}

// archivePackageURL returns the PURL for a FreeBSD package parsed from a pkgng archive (.pkg) file. The ABI
// field is used for the "arch" qualifier (rather than Arch) since it matches the format recorded in the pkgng
// database's "arch" column, keeping qualifiers consistent between packages found via either source.
func archivePackageURL(m pkg.FreeBSDPkgArchiveEntry) string {
	qualifiers := map[string]string{
		pkg.PURLQualifierArch: m.ABI,
		"origin":              m.Origin,
	}

	return packageurl.NewPackageURL(
		"freebsd",
		"",
		m.Name,
		m.Version,
		pkg.PURLQualifiers(qualifiers, nil),
		"",
	).ToString()
}
