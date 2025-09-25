package snap

import (
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

// newPackage creates a new Package from snap metadata
func newPackage(name, version string, metadata pkg.SnapEntry, locations ...file.Location) pkg.Package {
	p := pkg.Package{
		Name:      name,
		Version:   version,
		Locations: file.NewLocationSet(locations...),
		PURL:      packageURL(name, version, metadata),
		Type:      pkg.DebPkg, // Use Debian package type for compatibility
		Metadata:  metadata,
	}

	p.SetID()

	return p
}

// packageURL returns the PURL for a snap package
func packageURL(name, version string, metadata pkg.SnapEntry) string {
	var qualifiers packageurl.Qualifiers

	if metadata.Architecture != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "arch",
			Value: metadata.Architecture,
		})
	}

	if metadata.Base != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "base",
			Value: metadata.Base,
		})
	}

	if metadata.SnapType != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "type",
			Value: metadata.SnapType,
		})
	}

	return packageurl.NewPackageURL(
		packageurl.TypeGeneric,
		"snap",
		name,
		version,
		qualifiers,
		"",
	).ToString()
}

// newDebianPackageFromSnap creates a Debian-style package entry from snap manifest data
func newDebianPackageFromSnap(name, version string, snapMetadata pkg.SnapEntry, locations ...file.Location) pkg.Package {
	p := pkg.Package{
		Name:      name,
		Version:   version,
		Locations: file.NewLocationSet(locations...),
		Type:      pkg.DebPkg,
		PURL:      debianPackageURL(name, version, snapMetadata.Architecture),
		Metadata:  snapMetadata,
	}

	p.SetID()
	return p
}

// debianPackageURL creates a PURL for Debian packages found in snaps
func debianPackageURL(name, version, architecture string) string {
	var qualifiers packageurl.Qualifiers

	if architecture != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "arch",
			Value: architecture,
		})
	}

	return packageurl.NewPackageURL(
		packageurl.TypeDebian,
		"ubuntu", // Assume Ubuntu since most snaps are built on Ubuntu
		name,
		version,
		qualifiers,
		"",
	).ToString()
}
