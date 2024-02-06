package php

import (
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func newComposerLockPackage(pd parsedLockData, indexLocation file.Location) pkg.Package {
	p := pkg.Package{
		Name:      pd.Name,
		Version:   pd.Version,
		Locations: file.NewLocationSet(indexLocation.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
		Licenses:  pkg.NewLicenseSet(pkg.NewLicensesFromLocation(indexLocation, pd.License...)...),
		PURL:      packageURL(pd.Name, pd.Version),
		Language:  pkg.PHP,
		Type:      pkg.PhpComposerPkg,
		Metadata:  pd.PhpComposerLockEntry,
	}

	p.SetID()
	return p
}

func newComposerInstalledPackage(pd parsedInstalledData, indexLocation file.Location) pkg.Package {
	p := pkg.Package{
		Name:      pd.Name,
		Version:   pd.Version,
		Locations: file.NewLocationSet(indexLocation.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
		Licenses:  pkg.NewLicenseSet(pkg.NewLicensesFromLocation(indexLocation, pd.License...)...),
		PURL:      packageURL(pd.Name, pd.Version),
		Language:  pkg.PHP,
		Type:      pkg.PhpComposerPkg,
		Metadata:  pd.PhpComposerInstalledEntry,
	}

	p.SetID()
	return p
}

func newPeclPackage(pd pkg.PhpPeclEntry, indexLocation file.Location) pkg.Package {
	p := pkg.Package{
		Name:      pd.Name,
		Version:   pd.Version,
		Locations: file.NewLocationSet(indexLocation.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
		Licenses:  pkg.NewLicenseSet(pkg.NewLicensesFromLocation(indexLocation, pd.License...)...),
		PURL:      packageURLFromPecl(pd.Name, pd.Version),
		Language:  pkg.PHP,
		Type:      pkg.PhpPeclPkg,
		Metadata:  pd,
	}

	p.SetID()
	return p
}

func packageURL(name, version string) string {
	var pkgName, vendor string
	fields := strings.Split(name, "/")
	switch len(fields) {
	case 0:
		return ""
	case 1:
		pkgName = name
	case 2:
		vendor = fields[0]
		pkgName = fields[1]
	default:
		vendor = fields[0]
		pkgName = strings.Join(fields[1:], "-")
	}

	pURL := packageurl.NewPackageURL(
		packageurl.TypeComposer,
		vendor,
		pkgName,
		version,
		nil,
		"")
	return pURL.ToString()
}

func packageURLFromPecl(pkgName, version string) string {
	pURL := packageurl.NewPackageURL(
		"pecl",
		"",
		pkgName,
		version,
		nil,
		"")
	return pURL.ToString()
}
