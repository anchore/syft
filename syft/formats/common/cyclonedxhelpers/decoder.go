package cyclonedxhelpers

import (
	"fmt"
	"io"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/formats/common"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func GetValidator(format cyclonedx.BOMFileFormat) sbom.Validator {
	return func(reader io.Reader) error {
		bom := &cyclonedx.BOM{}
		err := cyclonedx.NewBOMDecoder(reader, format).Decode(bom)
		if err != nil {
			return err
		}
		// random JSON does not necessarily cause an error (e.g. SPDX)
		if (cyclonedx.BOM{} == *bom || bom.Components == nil) {
			return fmt.Errorf("not a valid CycloneDX document")
		}
		return nil
	}
}

func GetDecoder(format cyclonedx.BOMFileFormat) sbom.Decoder {
	return func(reader io.Reader) (*sbom.SBOM, error) {
		bom := &cyclonedx.BOM{
			Components: &[]cyclonedx.Component{},
		}
		err := cyclonedx.NewBOMDecoder(reader, format).Decode(bom)
		if err != nil {
			return nil, err
		}
		s, err := ToSyftModel(bom)
		if err != nil {
			return nil, err
		}
		return s, nil
	}
}

func ToSyftModel(bom *cyclonedx.BOM) (*sbom.SBOM, error) {
	if bom == nil {
		return nil, fmt.Errorf("no content defined in CycloneDX BOM")
	}

	idMap := make(map[string]interface{})

	s := &sbom.SBOM{
		Artifacts: sbom.Artifacts{
			PackageCatalog:     pkg.NewCatalog(),
			LinuxDistributions: linuxReleasesFromComponents(*bom.Components),
		},
		Sources:    extractSources(bom.Metadata, idMap),
		Descriptor: extractDescriptor(bom.Metadata),
	}

	if err := collectBomPackages(bom, s, idMap); err != nil {
		return nil, err
	}

	collectDependencyRelationships(bom, s, idMap)
	collectCompositionRelationships(bom, s, idMap)

	return s, nil
}

func collectBomPackages(bom *cyclonedx.BOM, s *sbom.SBOM, idMap map[string]interface{}) error {
	if bom.Components == nil {
		return fmt.Errorf("no components are defined in the CycloneDX BOM")
	}
	for i := range *bom.Components {
		collectPackages(&(*bom.Components)[i], s, idMap)
	}
	return nil
}

func collectPackages(component *cyclonedx.Component, s *sbom.SBOM, idMap map[string]interface{}) {
	switch component.Type {
	case cyclonedx.ComponentTypeOS:
	case cyclonedx.ComponentTypeContainer:
	case cyclonedx.ComponentTypeApplication, cyclonedx.ComponentTypeFramework, cyclonedx.ComponentTypeLibrary:
		p := *decodeComponent(component)
		// TODO there must be a better way than needing to call this manually:
		p.SetID()
		idMap[component.BOMRef] = p
		s.Artifacts.PackageCatalog.Add(p)
	}

	if component.Components != nil {
		for i := range *component.Components {
			collectPackages(&(*component.Components)[i], s, idMap)
		}
	}
}

func linuxReleasesFromComponents(components []cyclonedx.Component) []linux.Release {
	var out []linux.Release
	for i := range components {
		component := &components[i]
		if component.Type == cyclonedx.ComponentTypeOS {
			rel := linuxReleaseFromOSComponent(component)
			if rel == nil {
				continue
			}
			out = append(out, *rel)
		}
	}
	return out
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
		OSID:       name,
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

	if component.Properties != nil {
		values := map[string]string{}
		for _, p := range *component.Properties {
			values[p.Name] = p.Value
		}
		common.DecodeInto(&rel, values, "syft:distro", CycloneDXFields)
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

func collectDependencyRelationships(bom *cyclonedx.BOM, s *sbom.SBOM, idMap map[string]interface{}) {
	if bom.Dependencies == nil {
		return
	}
	for _, d := range *bom.Dependencies {
		if d.Dependencies == nil {
			continue
		}
		from, fromOk := idMap[d.Ref].(artifact.Identifiable)
		if !fromOk {
			continue
		}
		for _, t := range *d.Dependencies {
			to, toOk := idMap[t.Ref].(artifact.Identifiable)
			if !toOk {
				continue
			}
			// FIXME the relationshipType information is lost
			relationshipType := artifact.DependencyOfRelationship
			if _, ok := to.(*source.Metadata); ok {
				relationshipType = artifact.SourceRelationship
			}
			s.Relationships = append(s.Relationships, artifact.Relationship{
				From: from,
				To:   to,
				Type: relationshipType,
			})
		}
	}
}

func collectCompositionRelationships(bom *cyclonedx.BOM, s *sbom.SBOM, idMap map[string]interface{}) {
	if bom.Compositions != nil {
		for _, c := range *bom.Compositions {
			// if c.Aggregate == cyclonedx.CompositionAggregateComplete
			if c.Assemblies == nil || c.Dependencies == nil {
				continue
			}
			for _, f := range *c.Assemblies {
				from, fromOk := idMap[string(f)].(artifact.Identifiable)
				if !fromOk {
					continue
				}
				for _, t := range *c.Dependencies {
					to, toOk := idMap[string(t)].(artifact.Identifiable)
					if !toOk {
						continue
					}
					// FIXME the relationshipType information is lost
					relationshipType := artifact.DependencyOfRelationship
					if _, ok := to.(*source.Metadata); ok {
						relationshipType = artifact.SourceRelationship
					}
					s.Relationships = append(s.Relationships, artifact.Relationship{
						From: from,
						To:   to,
						Type: relationshipType,
					})
				}
			}
		}
	}
}

func extractSources(meta *cyclonedx.Metadata, idMap map[string]interface{}) []source.Metadata {
	if meta == nil || meta.Component == nil {
		return nil
	}
	return extractComponentSources(*meta.Component, idMap)
}

func extractComponentSources(c cyclonedx.Component, idMap map[string]interface{}) []source.Metadata {
	image := source.ImageMetadata{
		UserInput:      c.Name,
		ID:             c.Description,
		ManifestDigest: c.Version,
	}

	var sources []source.Metadata

	switch c.Type {
	case cyclonedx.ComponentTypeContainer:
		sources = append(sources, source.Metadata{
			Scheme:        source.ImageScheme,
			ImageMetadata: image,
		})
	case cyclonedx.ComponentTypeFile:
		sources = append(sources, source.Metadata{
			Scheme:        source.FileScheme, // or source.DirectoryScheme
			Path:          c.Name,
			ImageMetadata: image,
		})
	}

	for i := range sources {
		idMap[c.BOMRef] = &sources[i]
	}

	if c.Components != nil {
		for _, child := range *c.Components {
			sources = append(sources, extractComponentSources(child, idMap)...)
		}
	}

	return sources
}

// if there is more than one tool in meta.Tools' list the last item will be used
// as descriptor. If there is a way to know which tool to use here please fix it.
func extractDescriptor(meta *cyclonedx.Metadata) (desc sbom.Descriptor) {
	if meta == nil || meta.Tools == nil {
		return
	}

	for _, t := range *meta.Tools {
		desc.Name = t.Name
		desc.Version = t.Version
	}

	return
}
