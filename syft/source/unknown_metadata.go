package source

import "github.com/CycloneDX/cyclonedx-go"

// UnknownMetadata represents the CycloneComponentType that Syft doesn't support at present
type UnknownMetadata struct {
	UserInput   string                             `json:"name" yaml:"name"`
	ID          string                             `json:"bom-ref" yaml:"bom-ref"`
	Version     string                             `json:"version" yaml:"version"`
	Group       string                             `json:"group,omitempty" yaml:"group,omitempty"`
	Description string                             `json:"description,omitempty" yaml:"description,omitempty"`
	PackageURL  string                             `json:"purl" yaml:"purl"`
	Licenses    *cyclonedx.Licenses                `json:"licenses,omitempty" xml:"licenses,omitempty"`
	ExternalRef *[]cyclonedx.ExternalReference     `json:"externalRef,omitempty" yaml:"externalRef,omitempty"`
	Authors     *[]cyclonedx.OrganizationalContact `json:"authors,omitempty" xml:"authors>author,omitempty"`
}
