package php

import (
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func newComposerLockPackage(m parsedData, location ...source.Location) pkg.Package {
	var licenseLocation source.Location
	if len(location) > 0 {
		// we want to use the composer lock location as the source for the license declaration
		licenseLocation = location[0]
	}

	licenses := make([]pkg.License, 0)
	for _, l := range m.License {
		licenses = append(licenses, pkg.NewLicense(l, "", licenseLocation))
	}
	p := pkg.Package{
		Name:         m.Name,
		Version:      m.Version,
		Locations:    source.NewLocationSet(location...),
		Licenses:     licenses,
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
