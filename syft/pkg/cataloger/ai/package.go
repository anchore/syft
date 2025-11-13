package ai

import (
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func newGGUFPackage(metadata *pkg.GGUFFileHeader, modelName, version, license string, locations ...file.Location) pkg.Package {
	p := pkg.Package{
		Name:      modelName,
		Version:   version,
		Locations: file.NewLocationSet(locations...),
		Type:      pkg.ModelPkg,
		Licenses:  pkg.NewLicenseSet(pkg.NewLicensesFromValues(license)...),
		Metadata:  *metadata,
		// NOTE: PURL is intentionally not set as the package-url spec
		// has not yet finalized support for ML model packages
	}
	p.SetID()

	return p
}
