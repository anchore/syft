package bun

import (
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func newBunLockPackage(location file.Location, p bunPackage) pkg.Package {
	pack := pkg.Package{
		Name:      p.Name,
		Version:   p.Version,
		Locations: file.NewLocationSet(location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
		PURL:      packageURL(p.Name, p.Version),
		Language:  pkg.JavaScript,
		Type:      pkg.NpmPkg,
		Metadata: pkg.BunLockEntry{
			Resolved:     p.Resolved,
			Integrity:    p.Integrity,
			Dependencies: p.Dependencies,
		},
	}

	pack.SetID()

	return pack
}

func packageURL(name, version string) string {
	var namespace string

	if scope, rest, found := strings.Cut(name, "/"); found {
		namespace = scope
		name = rest
	}

	return packageurl.NewPackageURL(
		packageurl.TypeNPM,
		namespace,
		name,
		version,
		nil,
		"",
	).ToString()
}
