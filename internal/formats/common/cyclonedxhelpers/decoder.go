package cyclonedxhelpers

import (
	"fmt"
	"io"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func GetValidator(format cyclonedx.BOMFileFormat) format.Validator {
	return func(reader io.Reader) error {
		bom := &cyclonedx.BOM{}
		err := cyclonedx.NewBOMDecoder(reader, format).Decode(bom)
		if err != nil {
			return err
		}
		// random JSON does not necessarily cause an error (e.g. SPDX)
		if (cyclonedx.BOM{} == *bom) {
			return fmt.Errorf("Not a valid CycloneDX document")
		}
		return nil
	}
}

func GetDecoder(format cyclonedx.BOMFileFormat) format.Decoder {
	return func(reader io.Reader) (*sbom.SBOM, error) {
		bom := &cyclonedx.BOM{}
		err := cyclonedx.NewBOMDecoder(reader, format).Decode(bom)
		if err != nil {
			return nil, err
		}
		s, err := toSyftModel(bom)
		if err != nil {
			return nil, err
		}
		return s, nil
	}
}

func toSyftModel(bom *cyclonedx.BOM) (*sbom.SBOM, error) {
	s := &sbom.SBOM{
		Artifacts: sbom.Artifacts{
			PackageCatalog:    pkg.NewCatalog(),
			LinuxDistribution: linuxReleaseFromComponents(*bom.Components),
		},
		Source: decodeMetadata(bom.Metadata.Component),
		//Descriptor:    sbom.Descriptor{},
	}

	idMap := make(map[string]interface{})

	if err := collectBomPackages(bom, s, idMap); err != nil {
		return nil, err
	}

	if err := collectRelationships(bom, s, idMap); err != nil {
		return nil, err
	}

	return s, nil
}

func collectBomPackages(bom *cyclonedx.BOM, s *sbom.SBOM, idMap map[string]interface{}) error {
	if bom.Components == nil {
		return fmt.Errorf("No components are defined in the CycloneDX BOM")
	}
	for _, component := range *bom.Components {
		if err := collectPackages(&component, s, idMap); err != nil {
			return err
		}
	}
	return nil
}

func collectPackages(component *cyclonedx.Component, s *sbom.SBOM, idMap map[string]interface{}) error {
	switch component.Type {
	case cyclonedx.ComponentTypeOS:
	case cyclonedx.ComponentTypeContainer:
	case cyclonedx.ComponentTypeApplication, cyclonedx.ComponentTypeFramework, cyclonedx.ComponentTypeLibrary:
		p, err := decodeComponent(component)
		if err != nil {
			return err
		}
		idMap[component.BOMRef] = p
		// TODO there must be a better way than needing to call this manually:
		p.SetID()
		s.Artifacts.PackageCatalog.Add(*p)
	}

	if component.Components != nil {
		for _, c := range *component.Components {
			collectPackages(&c, s, idMap)
		}
	}

	return nil
}

func linuxReleaseFromComponents(components []cyclonedx.Component) *linux.Release {
	for _, component := range components {
		if component.Type == cyclonedx.ComponentTypeOS {
			return linuxReleaseFromOSComponent(&component)
		}
	}
	return nil
}

func linuxReleaseFromOSComponent(component *cyclonedx.Component) *linux.Release {
	if component == nil {
		return nil
	}

	var name string
	var version string
	if component.SWID != nil {
		name = component.SWID.Name
		version = component.SWID.Version
	}
	if name == "" {
		name = component.Name
	}
	if name == "" {
		name = getPropertyValue(component, "id")
	}
	if version == "" {
		version = component.Version
	}
	if version == "" {
		version = getPropertyValue(component, "versionID")
	}

	rel := &linux.Release{
		CPEName:    component.CPE,
		PrettyName: name,
		Name:       name,
		ID:         name,
		IDLike:     []string{name},
		Version:    version,
		VersionID:  version,
	}
	if component.ExternalReferences != nil {
		for _, ref := range *component.ExternalReferences {
			switch ref.Type {
			case cyclonedx.ERTypeIssueTracker:
				rel.BugReportURL = ref.URL
			case cyclonedx.ERTypeWebsite:
				rel.HomeURL = ref.URL
			case cyclonedx.ERTypeOther:
				switch ref.Comment {
				case "support":
					rel.SupportURL = ref.URL
				case "privacyPolicy":
					rel.PrivacyPolicyURL = ref.URL
				}
			}
		}
	}

	return rel
}

func getPropertyValue(component *cyclonedx.Component, name string) string {
	if component.Properties != nil {
		for _, p := range *component.Properties {
			if p.Name == name {
				return p.Value
			}
		}
	}
	return ""
}

// used to indicate that a relationship listed under the syft artifact package can be represented as a cyclonedx dependency.
// NOTE: CycloneDX provides the ability to describe components and their dependency on other components.
// The dependency graph is capable of representing both direct and transitive relationships.
// If a relationship is either direct or transitive it can be included in this function.
// An example of a relationship to not include would be: OwnershipByFileOverlapRelationship.
func _isExpressiblePackageRelationship(ty artifact.RelationshipType) bool {
	switch ty {
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

func collectRelationships(bom *cyclonedx.BOM, s *sbom.SBOM, idMap map[string]interface{}) error {
	if bom.Dependencies == nil {
		return nil
	}
	for _, d := range *bom.Dependencies {
		from, fromOk := idMap[d.Ref].(artifact.Identifiable)
		if fromOk {
			if d.Dependencies == nil {
				continue
			}
			for _, t := range *d.Dependencies {
				to, toOk := idMap[t.Ref].(artifact.Identifiable)
				if toOk {
					s.Relationships = append(s.Relationships, artifact.Relationship{
						From: from,
						To:   to,
						Type: artifact.DependencyOfRelationship, // FIXME this information is lost
					})
				}
			}
		}
	}
	return nil
}

func decodeMetadata(component *cyclonedx.Component) source.Metadata {
	switch component.Type {
	case cyclonedx.ComponentTypeContainer:
		return source.Metadata{
			Scheme: source.ImageScheme,
			ImageMetadata: source.ImageMetadata{
				UserInput:      component.Name,
				ID:             component.BOMRef,
				ManifestDigest: component.Version,
			},
		}
	case cyclonedx.ComponentTypeFile:
		return source.Metadata{
			Scheme: source.FileScheme, // or source.DirectoryScheme
			Path:   component.Name,
			ImageMetadata: source.ImageMetadata{
				UserInput:      component.Name,
				ID:             component.BOMRef,
				ManifestDigest: component.Version,
			},
		}
	}
	return source.Metadata{}
}
