package pkg

import "github.com/package-url/packageurl-go"

// JavaMetadata encapsulates all Java ecosystem metadata for a package as well as an (optional) parent relationship.
type JavaMetadata struct {
	VirtualPath   string         `json:"virtualPath"`
	Manifest      *JavaManifest  `mapstructure:"Manifest" json:"manifest,omitempty"`
	PomProperties *PomProperties `mapstructure:"PomProperties" json:"pomProperties,omitempty"`
	Parent        *Package       `json:"-"`
}

// PomProperties represents the fields of interest extracted from a Java archive's pom.xml file.
type PomProperties struct {
	Path       string            `mapstructure:"path" json:"path"`
	Name       string            `mapstructure:"name" json:"name"`
	GroupID    string            `mapstructure:"groupId" json:"groupId"`
	ArtifactID string            `mapstructure:"artifactId" json:"artifactId"`
	Version    string            `mapstructure:"version" json:"version"`
	Extra      map[string]string `mapstructure:",remain" json:"extraFields"`
}

// JavaManifest represents the fields of interest extracted from a Java archive's META-INF/MANIFEST.MF file.
type JavaManifest struct {
	Name            string              `mapstructure:"Name" json:"name,omitempty"`
	ManifestVersion string              `mapstructure:"Manifest-Version" json:"manifestVersion,omitempty"`
	SpecTitle       string              `mapstructure:"Specification-Title" json:"specificationTitle,omitempty"`
	SpecVersion     string              `mapstructure:"Specification-Version" json:"specificationVersion,omitempty"`
	SpecVendor      string              `mapstructure:"Specification-Vendor" json:"specificationVendor,omitempty"`
	ImplTitle       string              `mapstructure:"Implementation-Title" json:"implementationTitle,omitempty"`
	ImplVersion     string              `mapstructure:"Implementation-Version" json:"implementationVersion,omitempty"`
	ImplVendor      string              `mapstructure:"Implementation-Vendor" json:"implementationVendor,omitempty"`
	Extra           map[string]string   `mapstructure:",remain" json:"extraFields,omitempty"`
	Sections        []map[string]string `json:"sections,omitempty"`
}

func (m JavaMetadata) PackageURL() string {
	if m.PomProperties != nil {
		pURL := packageurl.NewPackageURL(
			packageurl.TypeMaven,
			m.PomProperties.GroupID,
			m.PomProperties.ArtifactID,
			m.PomProperties.Version,
			nil, // TODO: there are probably several qualifiers that can be specified here
			"")
		return pURL.ToString()
	}

	// TODO: support non-maven artifacts

	return ""
}
