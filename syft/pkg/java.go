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

// JavaArchive encapsulates all Java ecosystem metadata for a package as well as an (optional) parent relationship.
type JavaArchive struct {
	VirtualPath    string             `json:"virtualPath" cyclonedx:"virtualPath"` // we need to include the virtual path in cyclonedx documents to prevent deduplication of jars within jars
	Manifest       *JavaManifest      `mapstructure:"Manifest" json:"manifest,omitempty"`
	PomProperties  *JavaPomProperties `mapstructure:"PomProperties" json:"pomProperties,omitempty" cyclonedx:"-"`
	PomProject     *JavaPomProject    `mapstructure:"PomProject" json:"pomProject,omitempty"`
	ArchiveDigests []file.Digest      `hash:"ignore" json:"digest,omitempty"`
	Parent         *Package           `hash:"ignore" json:"-"` // note: the parent cannot be included in the minimal definition of uniqueness since this field is not reproducible in an encode-decode cycle (is lossy).
}

// JavaPomProperties represents the fields of interest extracted from a Java archive's pom.properties file.
type JavaPomProperties struct {
	Path       string            `mapstructure:"path" json:"path"`
	Name       string            `mapstructure:"name" json:"name"`
	GroupID    string            `mapstructure:"groupId" json:"groupId" cyclonedx:"groupID"`
	ArtifactID string            `mapstructure:"artifactId" json:"artifactId" cyclonedx:"artifactID"`
	Version    string            `mapstructure:"version" json:"version"`
	Scope      string            `mapstructure:"scope" json:"scope,omitempty"`
	Extra      map[string]string `mapstructure:",remain" json:"extraFields,omitempty"`
}

// JavaPomProject represents fields of interest extracted from a Java archive's pom.xml file. See https://maven.apache.org/ref/3.6.3/maven-model/maven.html for more details.
type JavaPomProject struct {
	Path        string         `json:"path"`
	Parent      *JavaPomParent `json:"parent,omitempty"`
	GroupID     string         `json:"groupId"`
	ArtifactID  string         `json:"artifactId"`
	Version     string         `json:"version"`
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	URL         string         `json:"url,omitempty"`
}

// JavaPomParent contains the fields within the <parent> tag in a pom.xml file
type JavaPomParent struct {
	GroupID    string `json:"groupId"`
	ArtifactID string `json:"artifactId"`
	Version    string `json:"version"`
}

// PkgTypeIndicated returns the package Type indicated by the data contained in the JavaPomProperties.
func (p JavaPomProperties) PkgTypeIndicated() Type {
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
