package cyclonedxhelpers

import (
	"fmt"
	"io"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/syft/internal/formats/common"
	"github.com/anchore/syft/syft/artifact"
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
		if (cyclonedx.BOM{} == *bom) {
			return fmt.Errorf("not a valid CycloneDX document")
		}
		return nil
	}
}

func GetDecoder(format cyclonedx.BOMFileFormat) sbom.Decoder {
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
	meta := source.Metadata{}
	if bom.Metadata != nil {
		meta = decodeMetadata(bom.Metadata.Component)
	}
	s := &sbom.SBOM{
		Artifacts: sbom.Artifacts{
			PackageCatalog:    pkg.NewCatalog(),
			LinuxDistribution: linuxReleaseFromComponents(*bom.Components),
		},
		Source: meta,
		//Descriptor:    sbom.Descriptor{},
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
		// TODO there must be a better way than needing to call this manually:
		p.SetID()
		s.Artifacts.PackageCatalog.Add(*p)
	}

	if component.Components != nil {
		for i := range *component.Components {
			collectPackages(&(*component.Components)[i], s, idMap)
		}
	}
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

func collectRelationships(bom *cyclonedx.BOM, s *sbom.SBOM, idMap map[string]interface{}) {
	if bom.Dependencies == nil {
		return
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
