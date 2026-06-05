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

// newSafeTensorsPackage creates a SafeTensors package with the given metadata
// and locations. Name and Licenses are intentionally not set here and done at the processor level
func newSafeTensorsPackage(metadata *pkg.SafeTensorsModelInfo, locations ...file.Location) pkg.Package {
	p := pkg.Package{
		Locations: file.NewLocationSet(locations...),
		Type:      pkg.ModelPkg,
		Metadata:  *metadata,
		// PURL is intentionally not set: package-url has not yet finalized ML model support.
	}
	p.SetID()

	return p
}
