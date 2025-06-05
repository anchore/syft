package source

// UnknownMetadata represents the CycloneComponentType that Syft doesn't support at present
type UnknownMetadata struct {
	UserInput   string                   `json:"name" yaml:"name"`
	ID          string                   `json:"bom-ref" yaml:"bom-ref"`
	Version     string                   `json:"version" yaml:"version"`
	Group       string                   `json:"group,omitempty" yaml:"group,omitempty"`
	Description string                   `json:"description,omitempty" yaml:"description,omitempty"`
	PackageURL  string                   `json:"purl" yaml:"purl"`
	Licenses    *[]LicenseChoice         `json:"licenses,omitempty" xml:"licenses,omitempty"`
	ExternalRef *[]ExternalReference     `json:"externalRef,omitempty" yaml:"externalRef,omitempty"`
	Authors     *[]OrganizationalContact `json:"authors,omitempty" xml:"authors>author,omitempty"`
}

type OrganizationalContact struct {
	Name string `json:"name,omitempty" xml:"name,omitempty"`
}

type ExternalReference struct {
	URL    string  `json:"url" xml:"url"`
	Hashes *[]Hash `json:"hashes,omitempty" xml:"hashes>hash,omitempty"`
	Type   string  `json:"type" xml:"type,attr"`
}

type Hash struct {
	Algorithm string `json:"alg" xml:"alg,attr"`
	Value     string `json:"content" xml:",chardata"`
}

type LicenseChoice struct {
	License *License `json:"license,omitempty" xml:"-"`
}

type License struct {
	ID string `json:"id,omitempty" xml:"id,omitempty"`
}

type ApplicationMetadata struct {
	UnknownMetadata
}

type LibraryMetadata struct {
	UnknownMetadata
}

type FrameworkMetadata struct {
	UnknownMetadata
}

type PlatformMetadata struct {
	UnknownMetadata
}

type OSMetadata struct {
	UnknownMetadata
}
