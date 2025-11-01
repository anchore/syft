package swipl

import (
	"context"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/licenses"
)

func newSwiplPackPackage(ctx context.Context, resolver file.Resolver, m pkg.SwiplPackEntry, locations ...file.Location) pkg.Package {
	p := pkg.Package{
		Name:      m.Name,
		Version:   m.Version,
		PURL:      swiplpackPackageURL(m.Name, m.Version),
		Locations: file.NewLocationSet(locations...),
		Licenses:  pkg.NewLicenseSet(licenses.FindRelativeToLocations(ctx, resolver, locations...)...),
		Type:      pkg.SwiplPackPkg,
		Language:  pkg.Swipl,
		Metadata:  m,
	}

	p.SetID()

	return p
}

func swiplpackPackageURL(name, version string) string {
	var qualifiers packageurl.Qualifiers

	return packageurl.NewPackageURL(
		"swiplpack",
		"",
		name,
		version,
		qualifiers,
		"",
	).ToString()
}
