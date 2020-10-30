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
	Main          map[string]string            `json:"main,omitempty"`
	NamedSections map[string]map[string]string `json:"namedSections,omitempty"`
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
