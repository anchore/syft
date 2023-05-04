package cyclonedxhelpers

import (
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func ToFormatModel(s sbom.SBOM) *cyclonedx.BOM {
	cdxBOM := cyclonedx.NewBOM()

	// NOTE(jonasagx): cycloneDX requires URN uuids (URN returns the RFC 2141 URN form of uuid):
	// https://github.com/CycloneDX/specification/blob/master/schema/bom-1.3-strict.schema.json#L36
	// "pattern": "^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
	cdxBOM.SerialNumber = uuid.New().URN()
	cdxBOM.Metadata = toBomDescriptor(internal.ApplicationName, s.Descriptor.Version, s.Source)

	packages := s.Artifacts.Packages.Sorted()
	components := make([]cyclonedx.Component, len(packages))
	for i, p := range packages {
		components[i] = encodeComponent(p)
	}
	components = append(components, toOSComponent(s.Artifacts.LinuxDistribution)...)
	cdxBOM.Components = &components

	dependencies := toDependencies(s.Relationships)
	if len(dependencies) > 0 {
		cdxBOM.Dependencies = &dependencies
	}

	return cdxBOM
}

func toOSComponent(distro *linux.Release) []cyclonedx.Component {
	if distro == nil {
		return []cyclonedx.Component{}
	}
	eRefs := &[]cyclonedx.ExternalReference{}
	if distro.BugReportURL != "" {
		*eRefs = append(*eRefs, cyclonedx.ExternalReference{
			URL:  distro.BugReportURL,
			Type: cyclonedx.ERTypeIssueTracker,
		})
	}
	if distro.HomeURL != "" {
		*eRefs = append(*eRefs, cyclonedx.ExternalReference{
			URL:  distro.HomeURL,
			Type: cyclonedx.ERTypeWebsite,
		})
	}
	if distro.SupportURL != "" {
		*eRefs = append(*eRefs, cyclonedx.ExternalReference{
			URL:     distro.SupportURL,
			Type:    cyclonedx.ERTypeOther,
			Comment: "support",
		})
	}
	if distro.PrivacyPolicyURL != "" {
		*eRefs = append(*eRefs, cyclonedx.ExternalReference{
			URL:     distro.PrivacyPolicyURL,
			Type:    cyclonedx.ERTypeOther,
			Comment: "privacyPolicy",
		})
	}
	if len(*eRefs) == 0 {
		eRefs = nil
	}
	props := encodeProperties(distro, "syft:distro")
	var properties *[]cyclonedx.Property
	if len(props) > 0 {
		properties = &props
	}
	return []cyclonedx.Component{
		{
			Type: cyclonedx.ComponentTypeOS,
			// FIXME is it idiomatic to be using SWID here for specific name and version information?
			SWID: &cyclonedx.SWID{
				TagID:   distro.ID,
				Name:    distro.ID,
				Version: distro.VersionID,
			},
			Description: distro.PrettyName,
			Name:        distro.ID,
			Version:     distro.VersionID,
			// TODO should we add a PURL?
			CPE:                formatCPE(distro.CPEName),
			ExternalReferences: eRefs,
			Properties:         properties,
		},
	}
}

func formatCPE(cpeString string) string {
	c, err := cpe.New(cpeString)
	if err != nil {
		log.Debugf("skipping invalid CPE: %s", cpeString)
		return ""
	}
	return cpe.String(c)
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

// used to indicate that a relationship listed under the syft artifact package can be represented as a cyclonedx dependency.
// NOTE: CycloneDX provides the ability to describe components and their dependency on other components.
// The dependency graph is capable of representing both direct and transitive relationships.
// If a relationship is either direct or transitive it can be included in this function.
// An example of a relationship to not include would be: OwnershipByFileOverlapRelationship.
func isExpressiblePackageRelationship(ty artifact.RelationshipType) bool {
	switch ty {
	case artifact.DependencyOfRelationship:
		return true
	default:
		return false
	}
}

func toDependencies(relationships []artifact.Relationship) []cyclonedx.Dependency {
	result := make([]cyclonedx.Dependency, 0)
	for _, r := range relationships {
		exists := isExpressiblePackageRelationship(r.Type)
		if !exists {
			log.Debugf("unable to convert relationship from CycloneDX 1.4 JSON, dropping: %+v", r)
			continue
		}

		// we only capture package-to-package relationships for now
		fromPkg, ok := r.From.(*pkg.Package)
		if !ok {
			continue
		}

		toPkg, ok := r.To.(*pkg.Package)
		if !ok {
			continue
		}

		// ind dep

		innerDeps := []string{}
		innerDeps = append(innerDeps, deriveBomRef(*fromPkg))
		result = append(result, cyclonedx.Dependency{
			Ref:          deriveBomRef(*toPkg),
			Dependencies: &innerDeps,
		})
	}
	return result
}

func toBomDescriptorComponent(srcMetadata source.Metadata) *cyclonedx.Component {
	name := srcMetadata.Name
	switch srcMetadata.Scheme {
	case source.ImageScheme:
		if name == "" {
			name = srcMetadata.ImageMetadata.UserInput
		}
		bomRef, err := artifact.IDByHash(srcMetadata.ImageMetadata.ID)
		if err != nil {
			log.Warnf("unable to get fingerprint of image metadata=%s: %+v", srcMetadata.ImageMetadata.ID, err)
		}
		return &cyclonedx.Component{
			BOMRef:  string(bomRef),
			Type:    cyclonedx.ComponentTypeContainer,
			Name:    name,
			Version: srcMetadata.ImageMetadata.ManifestDigest,
		}
	case source.DirectoryScheme, source.FileScheme:
		if name == "" {
			name = srcMetadata.Path
		}
		bomRef, err := artifact.IDByHash(srcMetadata.Path)
		if err != nil {
			log.Warnf("unable to get fingerprint of source metadata path=%s: %+v", srcMetadata.Path, err)
		}
		return &cyclonedx.Component{
			BOMRef: string(bomRef),
			Type:   cyclonedx.ComponentTypeFile,
			Name:   name,
		}
	}

	return nil
}
