package snap

import (
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

// SnapMetadata represents metadata for a snap package
type SnapMetadata struct {
	SnapType    string `json:"snapType" yaml:"snapType"`         // base, kernel, system, gadget, snapd
	Base        string `json:"base" yaml:"base"`                 // base snap name (e.g., core20, core22)
	SnapName    string `json:"snapName" yaml:"snapName"`         // name of the snap
	SnapVersion string `json:"snapVersion" yaml:"snapVersion"`   // version of the snap
	Architecture string `json:"architecture" yaml:"architecture"` // architecture (amd64, arm64, etc.)
}

const (
	SnapTypeBase   = "base"
	SnapTypeKernel = "kernel"
	SnapTypeApp    = "app"
	SnapTypeGadget = "gadget"
	SnapTypeSnapd  = "snapd"
)

// newPackage creates a new Package from snap metadata
func newPackage(name, version string, metadata SnapMetadata, locations ...file.Location) pkg.Package {
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
func packageURL(name, version string, metadata SnapMetadata) string {
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
func newDebianPackageFromSnap(name, version string, snapMetadata SnapMetadata, locations ...file.Location) pkg.Package {
	p := pkg.Package{
		Name:      name,
		Version:   version,
		Locations: file.NewLocationSet(locations...),
		Type:      pkg.DebPkg,
		PURL:      debianPackageURL(name, version),
		Metadata:  snapMetadata,
	}

	p.SetID()
	return p
}

// debianPackageURL creates a PURL for Debian packages found in snaps
func debianPackageURL(name, version string) string {
	return packageurl.NewPackageURL(
		packageurl.TypeDebian,
		"ubuntu", // Assume Ubuntu since most snaps are built on Ubuntu
		name,
		version,
		nil,
		"",
	).ToString()
}