package cyclonedxhelpers

import (
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/version"
	"github.com/anchore/syft/syft/artifact"
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
	cdxBOM.Metadata = toBomDescriptor(internal.ApplicationName, versionInfo.Version, s.Source)

	packages := s.Artifacts.PackageCatalog.Sorted()
	components := make([]cyclonedx.Component, len(packages))
	for i, p := range packages {
		components[i] = toComponent(p)
	}
	cdxBOM.Components = &components

	dependencies := toDependencies(s.Relationships)
	if len(dependencies) > 0 {
		cdxBOM.Dependencies = &dependencies
	}

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
		BOMRef:     string(p.ID()),
		Type:       cyclonedx.ComponentTypeLibrary,
		Name:       p.Name,
		Version:    p.Version,
		PackageURL: p.PURL,
		Licenses:   toLicenses(p.Licenses),
	}
}

func lookupRelationship(ty artifact.RelationshipType) bool {
	switch ty {
	case artifact.OwnershipByFileOverlapRelationship:
		return true
	case artifact.RuntimeDependencyOfRelationship:
		return true
	case artifact.DevDependencyOfRelationship:
		return true
	case artifact.BuildDependencyOfRelationship:
		return true
	case artifact.DependencyOfRelationship:
		return true
	}
	return false
}

func toDependencies(relationships []artifact.Relationship) []cyclonedx.Dependency {
	result := make([]cyclonedx.Dependency, 0)
	for _, r := range relationships {
		exists := lookupRelationship(r.Type)
		if !exists {
			log.Warnf("unable to convert relationship from CycloneDX 1.3 JSON, dropping: %+v", r)
			continue
		}

		innerDeps := []cyclonedx.Dependency{}
		innerDeps = append(innerDeps, cyclonedx.Dependency{Ref: string(r.From.ID())})
		result = append(result, cyclonedx.Dependency{
			Ref:          string(r.To.ID()),
			Dependencies: &innerDeps,
		})
	}
	return result
}

func toBomDescriptorComponent(srcMetadata source.Metadata) *cyclonedx.Component {
	switch srcMetadata.Scheme {
	case source.ImageScheme:
		bomRef, err := artifact.IDByHash(srcMetadata.ImageMetadata.ID)
		if err != nil {
			log.Warnf("unable to get fingerprint of image metadata=%s: %+v", srcMetadata.ImageMetadata.ID, err)
		}
		return &cyclonedx.Component{
			BOMRef:  string(bomRef),
			Type:    cyclonedx.ComponentTypeContainer,
			Name:    srcMetadata.ImageMetadata.UserInput,
			Version: srcMetadata.ImageMetadata.ManifestDigest,
		}
	case source.DirectoryScheme, source.FileScheme:
		bomRef, err := artifact.IDByHash(srcMetadata.Path)
		if err != nil {
			log.Warnf("unable to get fingerprint of source metadata path=%s: %+v", srcMetadata.Path, err)
		}
		return &cyclonedx.Component{
			BOMRef: string(bomRef),
			Type:   cyclonedx.ComponentTypeFile,
			Name:   srcMetadata.Path,
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
