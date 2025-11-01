package ruby

import (
	"context"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/licenses"
)

func newGemfileLockPackage(name, version string, locations ...file.Location) pkg.Package {
	p := pkg.Package{
		Name:      name,
		Version:   version,
		PURL:      packageURL(name, version),
		Locations: file.NewLocationSet(locations...),
		Language:  pkg.Ruby,
		Type:      pkg.GemPkg,
	}

	p.SetID()

	return p
}

func newGemspecPackage(ctx context.Context, resolver file.Resolver, m gemData, gemSpecLocation file.Location) pkg.Package {
	p := pkg.Package{
		Name:      m.Name,
		Version:   m.Version,
		Locations: file.NewLocationSet(gemSpecLocation.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
		Licenses:  pkg.NewLicenseSet(pkg.NewLicensesFromLocationWithContext(ctx, gemSpecLocation, m.Licenses...)...),
		PURL:      packageURL(m.Name, m.Version),
		Language:  pkg.Ruby,
		Type:      pkg.GemPkg,
		Metadata:  m.RubyGemspec,
	}

	p.SetID()

	p = licenses.RelativeToPackage(ctx, resolver, p)

	return p
}

func packageURL(name, version string) string {
	var qualifiers packageurl.Qualifiers

	return packageurl.NewPackageURL(
		packageurl.TypeGem,
		"",
		name,
		version,
		qualifiers,
		"",
	).ToString()
}
