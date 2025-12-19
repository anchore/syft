package macos

import (
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func newMacOSAppPackage(name, version, bundleID string, location file.Location) pkg.Package {
	p := pkg.Package{
		Name:      name,
		Version:   version,
		Type:      pkg.MacOSAppPkg,
		Locations: file.NewLocationSet(location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
		PURL:      packageURL(name, version),
		Metadata: pkg.MacOSAppEntry{
			BundleIdentifier: bundleID,
		},
	}

	p.SetID()
	return p
}

func packageURL(name, version string) string {
	return packageurl.NewPackageURL(
		"macos-app",
		"",
		name,
		version,
		nil,
		"",
	).ToString()
}
