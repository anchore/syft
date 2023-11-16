package swift

import (
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func newSwiftPackageManagerPackage(name, version, sourceURL, revision string, locations ...file.Location) pkg.Package {
	p := pkg.Package{
		Name:      name,
		Version:   version,
		PURL:      swiftPackageManagerPackageURL(name, version, sourceURL),
		Locations: file.NewLocationSet(locations...),
		Type:      pkg.SwiftPkg,
		Language:  pkg.Swift,
		Metadata: pkg.SwiftPackageManagerResolvedEntry{
			Revision: revision,
		},
	}

	p.SetID()

	return p
}

func newCocoaPodsPackage(name, version, hash string, locations ...file.Location) pkg.Package {
	p := pkg.Package{
		Name:      name,
		Version:   version,
		PURL:      cocoaPodsPackageURL(name, version),
		Locations: file.NewLocationSet(locations...),
		Type:      pkg.CocoapodsPkg,
		Language:  pkg.Swift,
		Metadata: pkg.CocoaPodfileLockEntry{
			Checksum: hash,
		},
	}

	p.SetID()

	return p
}

func cocoaPodsPackageURL(name, version string) string {
	var qualifiers packageurl.Qualifiers

	return packageurl.NewPackageURL(
		packageurl.TypeCocoapods,
		"",
		name,
		version,
		qualifiers,
		"",
	).ToString()
}

func swiftPackageManagerPackageURL(name, version, sourceURL string) string {
	var qualifiers packageurl.Qualifiers

	return packageurl.NewPackageURL(
		packageurl.TypeSwift,
		strings.Replace(sourceURL, "https://", "", 1),
		name,
		version,
		qualifiers,
		"",
	).ToString()
}
