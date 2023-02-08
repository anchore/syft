package python

import (
	"fmt"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func newPackageForIndex(name, version string, locations ...source.Location) pkg.Package {
	p := pkg.Package{
		Name:      name,
		Version:   version,
		Locations: source.NewLocationSet(locations...),
		PURL:      packageURL(name, version, nil),
		Language:  pkg.Python,
		Type:      pkg.PythonPkg,
	}

	p.SetID()

	return p
}

func newPackageForIndexWithMetadata(name, version string, metadata pkg.PythonPipfileLockMetadata, locations ...source.Location) pkg.Package {
	p := pkg.Package{
		Name:         name,
		Version:      version,
		Locations:    source.NewLocationSet(locations...),
		PURL:         packageURL(name, version, nil),
		Language:     pkg.Python,
		Type:         pkg.PythonPkg,
		MetadataType: pkg.PythonPipfileLockMetadataType,
		Metadata:     metadata,
	}

	p.SetID()

	return p
}

func newPackageForPackage(m pkg.PythonPackageMetadata, sources ...source.Location) pkg.Package {
	var licenses []string
	if m.License != "" {
		licenses = []string{m.License}
	}

	p := pkg.Package{
		Name:         m.Name,
		Version:      m.Version,
		PURL:         packageURL(m.Name, m.Version, &m),
		Locations:    source.NewLocationSet(sources...),
		Licenses:     internal.LogicalStrings{Simple: licenses},
		Language:     pkg.Python,
		Type:         pkg.PythonPkg,
		MetadataType: pkg.PythonPackageMetadataType,
		Metadata:     m,
	}

	p.SetID()
	return p
}

func packageURL(name, version string, m *pkg.PythonPackageMetadata) string {
	// generate a purl from the package data
	pURL := packageurl.NewPackageURL(
		packageurl.TypePyPi,
		"",
		name,
		version,
		purlQualifiersForPackage(m),
		"")

	return pURL.ToString()
}

func purlQualifiersForPackage(m *pkg.PythonPackageMetadata) packageurl.Qualifiers {
	q := packageurl.Qualifiers{}
	if m == nil {
		return q
	}
	if m.DirectURLOrigin != nil {
		q = append(q, vcsURLQualifierForPackage(m.DirectURLOrigin)...)
	}
	return q
}

func vcsURLQualifierForPackage(p *pkg.PythonDirectURLOriginInfo) packageurl.Qualifiers {
	if p == nil || p.VCS == "" {
		return nil
	}
	// Taken from https://github.com/package-url/purl-spec/blob/master/PURL-SPECIFICATION.rst#known-qualifiers-keyvalue-pairs
	// packageurl-go still doesn't support all qualifier names
	return packageurl.Qualifiers{
		{Key: pkg.PURLQualifierVCSURL, Value: fmt.Sprintf("%s+%s@%s", p.VCS, p.URL, p.CommitID)},
	}
}
