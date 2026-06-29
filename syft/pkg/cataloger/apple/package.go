package apple

import (
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func newAppBundlePackage(name, version, bundleID string, location file.Location) pkg.Package {
	p := pkg.Package{
		Name:    name,
		Version: version,
		Type:    pkg.AppleAppBundlePkg,
		// note: there is no standard purl type for Apple app bundles, so we intentionally leave the PURL empty.
		Locations: file.NewLocationSet(location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
		Metadata: pkg.AppleAppBundleEntry{
			BundleIdentifier: bundleID,
		},
	}

	p.SetID()
	return p
}
