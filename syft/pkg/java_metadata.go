package pkg

import (
	"strings"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/file"
)

var jenkinsPluginPomPropertiesGroupIDs = []string{
	"io.jenkins.plugins",
	"org.jenkins.plugins",
	"org.jenkins-ci.plugins",
	"io.jenkins-ci.plugins",
	"com.cloudbees.jenkins.plugins",
}

// JavaMetadata encapsulates all Java ecosystem metadata for a package as well as an (optional) parent relationship.
type JavaMetadata struct {
	VirtualPath    string         `json:"virtualPath" cyclonedx:"virtualPath"` // we need to include the virtual path in cyclonedx documents to prevent deduplication of jars within jars
	Manifest       *JavaManifest  `mapstructure:"Manifest" json:"manifest,omitempty"`
	PomProperties  *PomProperties `mapstructure:"PomProperties" json:"pomProperties,omitempty" cyclonedx:"-"`
	PomProject     *PomProject    `mapstructure:"PomProject" json:"pomProject,omitempty"`
	ArchiveDigests []file.Digest  `hash:"ignore" json:"digest,omitempty"`
	Parent         *Package       `hash:"ignore" json:"-"` // note: the parent cannot be included in the minimal definition of uniqueness since this field is not reproducible in an encode-decode cycle (is lossy).
}

// PomProperties represents the fields of interest extracted from a Java archive's pom.properties file.
type PomProperties struct {
	Path       string            `mapstructure:"path" json:"path"`
	Name       string            `mapstructure:"name" json:"name"`
	GroupID    string            `mapstructure:"groupId" json:"groupId" cyclonedx:"groupID"`
	ArtifactID string            `mapstructure:"artifactId" json:"artifactId" cyclonedx:"artifactID"`
	Version    string            `mapstructure:"version" json:"version"`
	Scope      string            `mapstructure:"scope" json:"scope,omitempty"`
	Extra      map[string]string `mapstructure:",remain" json:"extraFields,omitempty"`
}

// PomProject represents fields of interest extracted from a Java archive's pom.xml file. See https://maven.apache.org/ref/3.6.3/maven-model/maven.html for more details.
type PomProject struct {
	Path        string     `json:"path"`
	Parent      *PomParent `json:"parent,omitempty"`
	GroupID     string     `json:"groupId"`
	ArtifactID  string     `json:"artifactId"`
	Version     string     `json:"version"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	URL         string     `json:"url,omitempty"`
}

// PomParent contains the fields within the <parent> tag in a pom.xml file
type PomParent struct {
	GroupID    string `json:"groupId"`
	ArtifactID string `json:"artifactId"`
	Version    string `json:"version"`
}

// PkgTypeIndicated returns the package Type indicated by the data contained in the PomProperties.
func (p PomProperties) PkgTypeIndicated() Type {
	if internal.HasAnyOfPrefixes(p.GroupID, jenkinsPluginPomPropertiesGroupIDs...) || strings.Contains(p.GroupID, ".jenkins.plugin") {
		return JenkinsPluginPkg
	}

	return JavaPkg
}

// JavaManifest represents the fields of interest extracted from a Java archive's META-INF/MANIFEST.MF file.
type JavaManifest struct {
	Main          map[string]string            `json:"main,omitempty"`
	NamedSections map[string]map[string]string `json:"namedSections,omitempty"`
}
