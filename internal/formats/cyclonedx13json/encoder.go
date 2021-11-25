package cyclonedx13json

import (
	"io"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/version"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/google/uuid"
)

func encoder(output io.Writer, s sbom.SBOM) error {
	bom := toFormatModel(s)
	enc := cyclonedx.NewBOMEncoder(output, cyclonedx.BOMFileFormatJSON)
	enc.SetPretty(true)

	err := enc.Encode(bom)
	return err
}

func toFormatModel(s sbom.SBOM) *cyclonedx.BOM {
	cdxBOM := cyclonedx.NewBOM()
	versionInfo := version.FromBuild()

	cdxBOM.SerialNumber = uuid.New().String()
	cdxBOM.Metadata = toBomDescriptor(internal.ApplicationName, versionInfo.Version, s.Source)

	packages := s.Artifacts.PackageCatalog.Sorted()
	components := make([]cyclonedx.Component, len(packages))
	for i, p := range packages {
		components[i] = toComponent(p)
	}
	cdxBOM.Components = &components

	return cdxBOM
}

// NewBomDescriptor returns a new BomDescriptor tailored for the current time and "syft" tool details.
func toBomDescriptor(name, version string, srcMetadata source.Metadata) *cyclonedx.Metadata {
	return &cyclonedx.Metadata{
		Timestamp: time.Now().Format(time.RFC3339),
		Tools: &[]cyclonedx.Tool{
			{
				Vendor:  "anchore",
				Name:    name,
				Version: version,
			},
		},
		Component: toBomDescriptorComponent(srcMetadata),
	}
}

func toComponent(p pkg.Package) cyclonedx.Component {
	return cyclonedx.Component{
		Type:       cyclonedx.ComponentTypeLibrary,
		Name:       p.Name,
		Version:    p.Version,
		PackageURL: p.PURL,
		Licenses:   toLicenses(p.Licenses),
	}
}

func toBomDescriptorComponent(srcMetadata source.Metadata) *cyclonedx.Component {
	switch srcMetadata.Scheme {
	case source.ImageScheme:
		return &cyclonedx.Component{
			Type:    cyclonedx.ComponentTypeContainer,
			Name:    srcMetadata.ImageMetadata.UserInput,
			Version: srcMetadata.ImageMetadata.ManifestDigest,
		}
	case source.DirectoryScheme:
		return &cyclonedx.Component{
			Type: cyclonedx.ComponentTypeFile,
			Name: srcMetadata.Path,
		}
	}

	return nil
}

func toLicenses(ls []string) *cyclonedx.Licenses {
	if len(ls) == 0 {
		return nil
	}

	lc := make(cyclonedx.Licenses, len(ls))
	for i, licenseName := range ls {
		lc[i] = cyclonedx.LicenseChoice{
			License: &cyclonedx.License{
				Name: licenseName,
			},
		}
	}

	return &lc
}
