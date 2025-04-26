package source

import "github.com/CycloneDX/cyclonedx-go"

// ApplicationMetadata represents the ComponentTypeApplication defined in CycloneDX
type ApplicationMetadata struct {
	UserInput   string                         `json:"name" yaml:"name"`
	ID          string                         `json:"bom-ref" yaml:"bom-ref"`
	Version     string                         `json:"version" yaml:"version"`
	Group       string                         `json:"group,omitempty" yaml:"group,omitempty"`
	Description string                         `json:"description,omitempty" yaml:"description,omitempty"`
	PackageURL  string                         `json:"purl" yaml:"purl"`
	ExternalRef *[]cyclonedx.ExternalReference `json:"externalRef,omitempty" yaml:"externalRef,omitempty"`
}

type ExternalReferencesMetadata struct {
	Type string `json:"type" yaml:"type"`
	URL  string `json:"url" yaml:"url"`
}
