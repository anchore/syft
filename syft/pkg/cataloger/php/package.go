package php

import (
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func newComposerLockPackage(m parsedData, indexLocation file.Location) pkg.Package {
	p := pkg.Package{
		Name:         m.Name,
		Version:      m.Version,
		Locations:    file.NewLocationSet(indexLocation),
		Licenses:     pkg.NewLicenseSet(pkg.NewLicensesFromLocation(indexLocation, m.License...)...),
		PURL:         packageURL(m),
		Language:     pkg.PHP,
		Type:         pkg.PhpComposerPkg,
		MetadataType: pkg.PhpComposerJSONMetadataType,
		Metadata:     m.PhpComposerJSONMetadata,
	}

	p.SetID()
	return p
}

func packageURL(m parsedData) string {
	var name, vendor string
	fields := strings.Split(m.Name, "/")
	switch len(fields) {
	case 0:
		return ""
	case 1:
		name = m.Name
	case 2:
		vendor = fields[0]
		name = fields[1]
	default:
		vendor = fields[0]
		name = strings.Join(fields[1:], "-")
	}

	pURL := packageurl.NewPackageURL(
		packageurl.TypeComposer,
		vendor,
		name,
		m.Version,
		nil,
		"")
	return pURL.ToString()
}
