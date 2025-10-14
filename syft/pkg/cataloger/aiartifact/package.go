package aiartifact

import (
	"fmt"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func newGGUFPackage(metadata *pkg.GGUFFileMetadata, locations ...file.Location) pkg.Package {
	p := pkg.Package{
		Name:      metadata.ModelName,
		Version:   metadata.ModelVersion,
		PURL:      packageURL(metadata),
		Locations: file.NewLocationSet(locations...),
		Type:      pkg.ModelPkg,
		Licenses:  pkg.NewLicenseSet(),
		Metadata:  *metadata,
	}

	// Add license to the package if present in metadata
	if metadata.License != "" {
		p.Licenses.Add(pkg.NewLicenseFromFields(metadata.License, "", nil))
	}

	p.SetID()

	return p
}

// packageURL returns the PURL for the specific GGUF model package (see https://github.com/package-url/purl-spec)
func packageURL(metadata *pkg.GGUFFileMetadata) string {
	var qualifiers packageurl.Qualifiers

	// Add model-specific qualifiers
	if metadata.Architecture != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "arch",
			Value: metadata.Architecture,
		})
	}

	if metadata.Quantization != "" && metadata.Quantization != "unknown" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "quantization",
			Value: metadata.Quantization,
		})
	}

	if metadata.Parameters > 0 {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "parameters",
			Value: fmt.Sprintf("%d", metadata.Parameters),
		})
	}

	// Use mlmodel as the type for machine learning models in GGUF format
	// This follows the PURL spec guidance for ML models
	return packageurl.NewPackageURL(
		"mlmodel",
		"gguf",
		metadata.ModelName,
		metadata.ModelVersion,
		qualifiers,
		"",
	).ToString()
}
