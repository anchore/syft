package pkg

import "github.com/package-url/packageurl-go"

// JavaMetadata encapsulates all Java ecosystem metadata for a package as well as an (optional) parent relationship.
type JavaMetadata struct {
	Manifest      *JavaManifest  `mapstructure:"Manifest" json:"manifest"`
	PomProperties *PomProperties `mapstructure:"PomProperties" json:"pom-properties"`
	Parent        *Package       `json:"parent-package"` // TODO: should this be included in the json output?
}

// PomProperties represents the fields of interest extracted from a Java archive's pom.xml file.
type PomProperties struct {
	Path       string
	Name       string            `mapstructure:"name" json:"name"`
	GroupID    string            `mapstructure:"groupId" json:"group-id"`
	ArtifactID string            `mapstructure:"artifactId" json:"artifact-id"`
	Version    string            `mapstructure:"version" json:"version"`
	Extra      map[string]string `mapstructure:",remain" json:"extra-fields"`
}

// JavaManifest represents the fields of interest extracted from a Java archive's META-INF/MANIFEST.MF file.
type JavaManifest struct {
	Name            string            `mapstructure:"Name" json:"name"`
	ManifestVersion string            `mapstructure:"Manifest-Version" json:"manifest-version"`
	SpecTitle       string            `mapstructure:"Specification-Title" json:"specification-title"`
	SpecVersion     string            `mapstructure:"Specification-Version" json:"specification-version"`
	SpecVendor      string            `mapstructure:"Specification-Vendor" json:"specification-vendor"`
	ImplTitle       string            `mapstructure:"Implementation-Title" json:"implementation-title"`
	ImplVersion     string            `mapstructure:"Implementation-Version" json:"implementation-version"`
	ImplVendor      string            `mapstructure:"Implementation-Vendor" json:"implementation-vendor"`
	Extra           map[string]string `mapstructure:",remain" json:"extra-fields"`
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
