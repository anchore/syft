package php

import (
	"context"
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func newComposerLockPackage(ctx context.Context, pd parsedLockData, indexLocation file.Location) pkg.Package {
	p := pkg.Package{
		Name:      pd.Name,
		Version:   pd.Version,
		Locations: file.NewLocationSet(indexLocation.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
		Licenses:  pkg.NewLicenseSet(pkg.NewLicensesFromLocationWithContext(ctx, indexLocation, pd.License...)...),
		PURL:      packageURLFromComposer(pd.Name, pd.Version),
		Language:  pkg.PHP,
		Type:      pkg.PhpComposerPkg,
		Metadata:  pd.PhpComposerLockEntry,
	}

	p.SetID()
	return p
}

func newComposerInstalledPackage(ctx context.Context, pd parsedInstalledData, indexLocation file.Location) pkg.Package {
	p := pkg.Package{
		Name:      pd.Name,
		Version:   pd.Version,
		Locations: file.NewLocationSet(indexLocation.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
		Licenses:  pkg.NewLicenseSet(pkg.NewLicensesFromLocationWithContext(ctx, indexLocation, pd.License...)...),
		PURL:      packageURLFromComposer(pd.Name, pd.Version),
		Language:  pkg.PHP,
		Type:      pkg.PhpComposerPkg,
		Metadata:  pd.PhpComposerInstalledEntry,
	}

	p.SetID()
	return p
}

func newPearPackage(ctx context.Context, pd peclPearData, indexLocation file.Location) pkg.Package {
	p := pkg.Package{
		Name:      pd.Name,
		Version:   pd.Version,
		Locations: file.NewLocationSet(indexLocation.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
		Licenses:  pkg.NewLicenseSet(pkg.NewLicensesFromLocationWithContext(ctx, indexLocation, pd.License...)...),
		PURL:      packageURLFromPear(pd.Name, pd.Channel, pd.Version),
		Language:  pkg.PHP,
		Type:      pkg.PhpPearPkg,
		Metadata:  pd.ToPear(),
	}

	p.SetID()
	return p
}

func newPeclPackage(ctx context.Context, pd peclPearData, indexLocation file.Location) pkg.Package {
	p := pkg.Package{
		Name:      pd.Name,
		Version:   pd.Version,
		Locations: file.NewLocationSet(indexLocation.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
		Licenses:  pkg.NewLicenseSet(pkg.NewLicensesFromLocationWithContext(ctx, indexLocation, pd.License...)...),
		PURL:      packageURLFromPear(pd.Name, pd.Channel, pd.Version),
		Language:  pkg.PHP,
		Type:      pkg.PhpPeclPkg,
		Metadata:  pd.ToPecl(),
	}

	p.SetID()
	return p
}

func packageURLFromComposer(name, version string) string {
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

func packageURLFromPear(pkgName, channel, version string) string {
	namespace := channel
	if namespace == "" {
		namespace = "pecl.php.net"
	}

	pURL := packageurl.NewPackageURL(
		"pear",
		namespace,
		pkgName,
		version,
		nil,
		"")
	return pURL.ToString()
}
