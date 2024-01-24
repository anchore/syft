package helpers

import (
	"fmt"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func ToSyftModel(bom *cyclonedx.BOM) (*sbom.SBOM, error) {
	if bom == nil {
		return nil, fmt.Errorf("no content defined in CycloneDX BOM")
	}

	s := &sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages:          pkg.NewCollection(),
			LinuxDistribution: linuxReleaseFromComponents(*bom.Components),
		},
		Source:     extractComponents(bom.Metadata),
		Descriptor: extractDescriptor(bom.Metadata),
	}

	idMap := make(map[string]interface{})

	if err := collectBomPackages(bom, s, idMap); err != nil {
		return nil, err
	}

	collectRelationships(bom, s, idMap)

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
		p := decodeComponent(component)
		idMap[component.BOMRef] = p
		syftID := extractSyftPacakgeID(component.BOMRef)
		if syftID != "" {
			idMap[syftID] = p
		}
		// TODO there must be a better way than needing to call this manually:
		p.SetID()
		s.Artifacts.Packages.Add(*p)
	}

	if component.Components != nil {
		for i := range *component.Components {
			collectPackages(&(*component.Components)[i], s, idMap)
		}
	}
}

func extractSyftPacakgeID(i string) string {
	instance, err := packageurl.FromString(i)
	if err != nil {
		return ""
	}
	for _, q := range instance.Qualifiers {
		if q.Key == "package-id" {
			return q.Value
		}
	}
	return ""
}

func linuxReleaseFromComponents(components []cyclonedx.Component) *linux.Release {
	for i := range components {
		component := &components[i]
		if component.Type == cyclonedx.ComponentTypeOS {
			return linuxReleaseFromOSComponent(component)
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

	if component.Properties != nil {
		values := map[string]string{}
		for _, p := range *component.Properties {
			values[p.Name] = p.Value
		}
		DecodeInto(&rel, values, "syft:distro", CycloneDXFields)
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

func collectRelationships(bom *cyclonedx.BOM, s *sbom.SBOM, idMap map[string]interface{}) {
	if bom.Dependencies == nil {
		return
	}
	for _, d := range *bom.Dependencies {
		if d.Dependencies == nil {
			continue
		}

		toPtr, toExists := idMap[d.Ref]
		if !toExists {
			continue
		}
		to, ok := PtrToStruct(toPtr).(artifact.Identifiable)
		if !ok {
			continue
		}

		for _, t := range *d.Dependencies {
			fromPtr, fromExists := idMap[t]
			if !fromExists {
				continue
			}
			from, ok := PtrToStruct(fromPtr).(artifact.Identifiable)
			if !ok {
				continue
			}
			s.Relationships = append(s.Relationships, artifact.Relationship{
				From: from,
				To:   to,
				// match assumptions in encoding, that this is the only type of relationship captured:
				Type: artifact.DependencyOfRelationship,
			})
		}
	}
}

func extractComponents(meta *cyclonedx.Metadata) source.Description {
	if meta == nil || meta.Component == nil {
		return source.Description{}
	}
	c := meta.Component

	switch c.Type {
	case cyclonedx.ComponentTypeContainer:
		var labels map[string]string

		if meta.Properties != nil {
			labels = decodeProperties(*meta.Properties, "syft:image:labels:")
		}

		return source.Description{
			ID: "",
			// TODO: can we decode alias name-version somehow? (it isn't be encoded in the first place yet)

			Metadata: source.StereoscopeImageSourceMetadata{
				UserInput:      c.Name,
				ID:             c.BOMRef,
				ManifestDigest: c.Version,
				Labels:         labels,
			},
		}
	case cyclonedx.ComponentTypeFile:
		// TODO: can we decode alias name-version somehow? (it isn't be encoded in the first place yet)

		// TODO: this is lossy... we can't know if this is a file or a directory
		return source.Description{
			ID:       "",
			Metadata: source.FileSourceMetadata{Path: c.Name},
		}
	}
	return source.Description{}
}

// if there is more than one tool in meta.Tools' list the last item will be used
// as descriptor. If there is a way to know which tool to use here please fix it.
func extractDescriptor(meta *cyclonedx.Metadata) (desc sbom.Descriptor) {
	if meta == nil || meta.Tools == nil {
		return
	}

	// handle 1.5 component element
	if meta.Tools.Components != nil {
		for _, t := range *meta.Tools.Components {
			desc.Name = t.Name
			desc.Version = t.Version
			return
		}
	}

	// handle pre-1.5 tool element
	if meta.Tools.Tools != nil {
		for _, t := range *meta.Tools.Tools {
			desc.Name = t.Name
			desc.Version = t.Version
			return
		}
	}

	return
}
