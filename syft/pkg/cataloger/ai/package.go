package ai

import (
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func newGGUFPackage(metadata *pkg.GGUFFileHeader, locations ...file.Location) pkg.Package {
	p := pkg.Package{
		Name:      metadata.ModelName,
		Version:   metadata.ModelVersion,
		Locations: file.NewLocationSet(locations...),
		Type:      pkg.ModelPkg,
		Licenses:  pkg.NewLicenseSet(),
		Metadata:  *metadata,
		// NOTE: PURL is intentionally not set as the package-url spec
		// has not yet finalized support for ML model packages
	}

	// Add license to the package if present in metadata
	if metadata.License != "" {
		p.Licenses.Add(pkg.NewLicenseFromFields(metadata.License, "", nil))
	}

	p.SetID()

	return p
}
