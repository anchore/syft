package python

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func normalize(name string) string {
	// https://packaging.python.org/en/latest/specifications/name-normalization/
	re := regexp.MustCompile(`[-_.]+`)
	normalized := re.ReplaceAllString(name, "-")
	return strings.ToLower(normalized)
}

func newPackageForIndex(name, version string, locations ...file.Location) pkg.Package {
	name = normalize(name)

	p := pkg.Package{
		Name:      name,
		Version:   version,
		Locations: file.NewLocationSet(locations...),
		PURL:      packageURL(name, version, nil),
		Language:  pkg.Python,
		Type:      pkg.PythonPkg,
	}

	p.SetID()

	return p
}

func newPackageForIndexWithMetadata(name, version string, metadata interface{}, locations ...file.Location) pkg.Package {
	name = normalize(name)

	p := pkg.Package{
		Name:      name,
		Version:   version,
		Locations: file.NewLocationSet(locations...),
		PURL:      packageURL(name, version, nil),
		Language:  pkg.Python,
		Type:      pkg.PythonPkg,
		Metadata:  metadata,
	}

	p.SetID()

	return p
}

func newPackageForRequirementsWithMetadata(name, version string, metadata pkg.PythonRequirementsEntry, locations ...file.Location) pkg.Package {
	name = normalize(name)

	p := pkg.Package{
		Name:      name,
		Version:   version,
		Locations: file.NewLocationSet(locations...),
		PURL:      packageURL(name, version, nil),
		Language:  pkg.Python,
		Type:      pkg.PythonPkg,
		Metadata:  metadata,
	}

	p.SetID()

	return p
}

func newPackageForPackage(m parsedData, licenses pkg.LicenseSet, sources ...file.Location) pkg.Package {
	name := normalize(m.Name)

	p := pkg.Package{
		Name:      name,
		Version:   m.Version,
		PURL:      packageURL(name, m.Version, &m.PythonPackage),
		Locations: file.NewLocationSet(sources...),
		Licenses:  licenses,
		Language:  pkg.Python,
		Type:      pkg.PythonPkg,
		Metadata:  m.PythonPackage,
	}

	p.SetID()

	return p
}

func packageURL(name, version string, m *pkg.PythonPackage) string {
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

func purlQualifiersForPackage(m *pkg.PythonPackage) packageurl.Qualifiers {
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
