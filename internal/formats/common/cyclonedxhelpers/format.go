package cyclonedxhelpers

import (
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/version"
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/google/uuid"
)

func ToFormatModel(s sbom.SBOM) *cyclonedx.BOM {
	cdxBOM := cyclonedx.NewBOM()
	versionInfo := version.FromBuild()

	// NOTE(jonasagx): cycloneDX requires URN uuids (URN returns the RFC 2141 URN form of uuid):
	// https://github.com/CycloneDX/specification/blob/master/schema/bom-1.3-strict.schema.json#L36
	// "pattern": "^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
	cdxBOM.SerialNumber = uuid.New().URN()
	cdxBOM.Metadata = toBomDescriptor(internal.ApplicationName, versionInfo.Version, s.Source, s.Artifacts.Distro)

	packages := s.Artifacts.PackageCatalog.Sorted()
	components := make([]cyclonedx.Component, len(packages))
	for i, p := range packages {
		components[i] = toComponent(p)
	}
	cdxBOM.Components = &components

	return cdxBOM
}

// NewBomDescriptor returns a new BomDescriptor tailored for the current time and "syft" tool details.
func toBomDescriptor(name, version string, srcMetadata source.Metadata, distro *distro.Distro) *cyclonedx.Metadata {
	metaData := cyclonedx.Metadata{
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
	if distro != nil {
		metaData.Properties = toBomDescriptorProperties(distro)
	}

	return &metaData
}

func toComponent(p pkg.Package) cyclonedx.Component {
	return cyclonedx.Component{
		Type:       cyclonedx.ComponentTypeLibrary,
		Name:       p.Name,
		Version:    p.Version,
		PackageURL: p.PURL,
		Licenses:   toLicenses(p.Licenses),
		Properties: toPackageProperties(p),
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
	case source.DirectoryScheme, source.FileScheme:
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

func toPackageProperties(p pkg.Package) *[]cyclonedx.Property {
	properties := prepareOrigin(p)
	properties = append(properties, prepareLocations(p.Locations)...)

	return &properties
}

func prepareOrigin(p pkg.Package) []cyclonedx.Property {
	properties := []cyclonedx.Property{}
	switch p.MetadataType {
	case pkg.DpkgMetadataType:
		metaData, _ := p.Metadata.(pkg.DpkgMetadata)
		properties = []cyclonedx.Property{
			{
				Name:  "source",
				Value: metaData.Source,
			},
		}
	case pkg.ApkMetadataType:
		metaData, _ := p.Metadata.(pkg.ApkMetadata)
		properties = []cyclonedx.Property{
			{
				Name:  "originPackage",
				Value: metaData.OriginPackage,
			},
		}
	case pkg.RpmdbMetadataType:
		metaData, _ := p.Metadata.(pkg.RpmdbMetadata)
		properties = []cyclonedx.Property{
			{
				Name:  "sourceRpm",
				Value: metaData.SourceRpm,
			},
		}
	case pkg.JavaMetadataType:
		metaData, _ := p.Metadata.(pkg.JavaMetadata)
		if metaData.PomProperties != nil {
			properties = []cyclonedx.Property{
				{
					Name:  "artifactId",
					Value: metaData.PomProperties.ArtifactID,
				},
				{
					Name:  "groupId",
					Value: metaData.PomProperties.GroupID,
				},
			}
		}
	}

	return properties
}

func prepareLocations(l []source.Location) []cyclonedx.Property {
	properties := []cyclonedx.Property{}
	for _, location := range l {
		properties = []cyclonedx.Property{
			{
				Name:  "path",
				Value: location.RealPath,
			},
			{
				Name:  "layerID",
				Value: location.FileSystemID,
			},
		}
	}

	return properties
}

func toBomDescriptorProperties(distro *distro.Distro) *[]cyclonedx.Property {
	properties := []cyclonedx.Property{
		{
			Name:  "distroName",
			Value: distro.Name(),
		},
		{
			Name:  "distroVersion",
			Value: distro.FullVersion(),
		},
	}

	return &properties
}
