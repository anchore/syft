package cyclonedxhelpers

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/format/internal/cyclonedxutil/helpers"
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
	cdxBOM.Metadata = toBomDescriptor(s.Descriptor.Name, s.Descriptor.Version, s.Source)

	packages := s.Artifacts.Packages.Sorted()
	components := make([]cyclonedx.Component, len(packages))
	for i, p := range packages {
		components[i] = helpers.EncodeComponent(p)
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
	props := helpers.EncodeProperties(distro, "syft:distro")
	var properties *[]cyclonedx.Property
	if len(props) > 0 {
		properties = &props
	}
	return []cyclonedx.Component{
		{
			BOMRef: toOSBomRef(distro.ID, distro.VersionID),
			Type:   cyclonedx.ComponentTypeOS,
			// is it idiomatic to be using SWID here for specific name and version information?
			SWID: &cyclonedx.SWID{
				TagID:   distro.ID,
				Name:    distro.ID,
				Version: distro.VersionID,
			},
			Description: distro.PrettyName,
			Name:        distro.ID,
			Version:     distro.VersionID,
			// should we add a PURL?
			CPE:                formatCPE(distro.CPEName),
			ExternalReferences: eRefs,
			Properties:         properties,
		},
	}
}

func toOSBomRef(name string, version string) string {
	if name == "" {
		return "os:unknown"
	}
	if version == "" {
		return fmt.Sprintf("os:%s", name)
	}
	return fmt.Sprintf("os:%s@%s", name, version)
}

func formatCPE(cpeString string) string {
	c, err := cpe.NewAttributes(cpeString)
	if err != nil {
		log.Debugf("skipping invalid CPE: %s", cpeString)
		return ""
	}
	return c.String()
}

// NewBomDescriptor returns a new BomDescriptor tailored for the current time and "syft" tool details.
func toBomDescriptor(name, version string, srcMetadata source.Description) *cyclonedx.Metadata {
	return &cyclonedx.Metadata{
		Timestamp: time.Now().Format(time.RFC3339),
		Tools: &cyclonedx.ToolsChoice{
			Components: &[]cyclonedx.Component{
				{
					Type:    cyclonedx.ComponentTypeApplication,
					Author:  "anchore",
					Name:    name,
					Version: version,
				},
			},
		},
		Properties: toBomProperties(srcMetadata),
		Component:  toBomDescriptorComponent(srcMetadata),
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
	dependencies := map[string]*cyclonedx.Dependency{}
	for _, r := range relationships {
		exists := isExpressiblePackageRelationship(r.Type)
		if !exists {
			log.Debugf("unable to convert relationship type to CycloneDX JSON, dropping: %#v", r)
			continue
		}

		// we only capture package-to-package relationships for now
		fromPkg, ok := r.From.(pkg.Package)
		if !ok {
			log.Tracef("unable to convert relationship fromPkg to CycloneDX JSON, dropping: %#v", r)
			continue
		}

		toPkg, ok := r.To.(pkg.Package)
		if !ok {
			log.Tracef("unable to convert relationship toPkg to CycloneDX JSON, dropping: %#v", r)
			continue
		}

		toRef := helpers.DeriveBomRef(toPkg)
		dep := dependencies[toRef]
		if dep == nil {
			dep = &cyclonedx.Dependency{
				Ref:          toRef,
				Dependencies: &[]string{},
			}
			dependencies[toRef] = dep
		}

		fromRef := helpers.DeriveBomRef(fromPkg)
		if !slices.Contains(*dep.Dependencies, fromRef) {
			*dep.Dependencies = append(*dep.Dependencies, fromRef)
		}
	}

	result := make([]cyclonedx.Dependency, 0, len(dependencies))
	for _, dep := range dependencies {
		slices.Sort(*dep.Dependencies)
		result = append(result, *dep)
	}

	slices.SortFunc(result, func(a, b cyclonedx.Dependency) int {
		return strings.Compare(a.Ref, b.Ref)
	})

	return result
}

func toBomProperties(srcMetadata source.Description) *[]cyclonedx.Property {
	metadata, ok := srcMetadata.Metadata.(source.StereoscopeImageSourceMetadata)
	if ok {
		props := helpers.EncodeProperties(metadata.Labels, "syft:image:labels")
		return &props
	}
	return nil
}

func toBomDescriptorComponent(srcMetadata source.Description) *cyclonedx.Component {
	name := srcMetadata.Name
	version := srcMetadata.Version
	switch metadata := srcMetadata.Metadata.(type) {
	case source.StereoscopeImageSourceMetadata:
		if name == "" {
			name = metadata.UserInput
		}
		if version == "" {
			version = metadata.ManifestDigest
		}
		bomRef, err := artifact.IDByHash(metadata.ID)
		if err != nil {
			log.Warnf("unable to get fingerprint of source image metadata=%s: %+v", metadata.ID, err)
		}
		return &cyclonedx.Component{
			BOMRef:  string(bomRef),
			Type:    cyclonedx.ComponentTypeContainer,
			Name:    name,
			Version: version,
		}
	case source.DirectorySourceMetadata:
		if name == "" {
			name = metadata.Path
		}
		bomRef, err := artifact.IDByHash(metadata.Path)
		if err != nil {
			log.Warnf("unable to get fingerprint of source directory metadata path=%s: %+v", metadata.Path, err)
		}
		return &cyclonedx.Component{
			BOMRef: string(bomRef),
			// TODO: this is lossy... we can't know if this is a file or a directory
			Type:    cyclonedx.ComponentTypeFile,
			Name:    name,
			Version: version,
		}
	case source.FileSourceMetadata:
		if name == "" {
			name = metadata.Path
		}
		bomRef, err := artifact.IDByHash(metadata.Path)
		if err != nil {
			log.Warnf("unable to get fingerprint of source file metadata path=%s: %+v", metadata.Path, err)
		}
		return &cyclonedx.Component{
			BOMRef: string(bomRef),
			// TODO: this is lossy... we can't know if this is a file or a directory
			Type:    cyclonedx.ComponentTypeFile,
			Name:    name,
			Version: version,
		}
	}

	return nil
}
