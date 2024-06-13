package pkg

import (
	"encoding/json"
	"fmt"
	stdSort "sort"
	"strings"

	"github.com/anchore/syft/syft/sort"

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
	Main     KeyValues   `json:"main,omitempty"`
	Sections []KeyValues `json:"sections,omitempty"`
}

func (m JavaManifest) Compare(other JavaManifest) int {
	if i := sort.Compare(m.Main, other.Main); i != 0 {
		return i
	}
	if i := sort.CompareArrays(m.Sections, other.Sections); i != 0 {
		return i
	}
	return 0
}
func (p JavaPomProperties) Compare(other JavaPomProperties) int {
	if i := sort.CompareOrd(p.Path, other.Path); i != 0 {
		return i
	}
	if i := sort.CompareOrd(p.Name, other.Name); i != 0 {
		return i
	}
	if i := sort.CompareOrd(p.GroupID, other.GroupID); i != 0 {
		return i
	}
	if i := sort.CompareOrd(p.ArtifactID, other.ArtifactID); i != 0 {
		return i
	}
	if i := sort.CompareOrd(p.Version, other.Version); i != 0 {
		return i
	}
	if i := sort.CompareOrd(p.Scope, other.Scope); i != 0 {
		return i
	}
	if i := sort.CompareMapOrd(p.Extra, other.Extra); i != 0 {
		return i
	}
	return 0
}
func (p JavaPomProject) Compare(other JavaPomProject) int {
	if i := sort.CompareOrd(p.Path, other.Path); i != 0 {
		return i
	}
	if i := sort.ComparePtr(p.Parent, other.Parent); i != 0 {
		return i
	}
	if i := sort.CompareOrd(p.GroupID, other.GroupID); i != 0 {
		return i
	}
	if i := sort.CompareOrd(p.ArtifactID, other.ArtifactID); i != 0 {
		return i
	}
	if i := sort.CompareOrd(p.Version, other.Version); i != 0 {
		return i
	}
	if i := sort.CompareOrd(p.Name, other.Name); i != 0 {
		return i
	}
	if i := sort.CompareOrd(p.Description, other.Description); i != 0 {
		return i
	}
	if i := sort.CompareOrd(p.URL, other.URL); i != 0 {
		return i
	}
	return 0
}
func (p JavaPomParent) Compare(other JavaPomParent) int {
	if i := sort.CompareOrd(p.GroupID, other.GroupID); i != 0 {
		return i
	}
	if i := sort.CompareOrd(p.ArtifactID, other.ArtifactID); i != 0 {
		return i
	}
	if i := sort.CompareOrd(p.Version, other.Version); i != 0 {
		return i
	}
	return 0
}
func (p JavaArchive) Compare(other JavaArchive) int {
	if i := sort.CompareOrd(p.VirtualPath, other.VirtualPath); i != 0 {
		return i
	}
	if i := sort.ComparePtr(p.Manifest, other.Manifest); i != 0 {
		return i
	}
	if i := sort.ComparePtr(p.PomProperties, other.PomProperties); i != 0 {
		return i
	}
	if i := sort.ComparePtr(p.PomProject, other.PomProject); i != 0 {
		return i
	}
	if i := sort.CompareArrays(p.ArchiveDigests, other.ArchiveDigests); i != 0 {
		return i
	}
	if i := sort.ComparePtr(p.Parent, other.Parent); i != 0 {
		return i
	}
	return 0
}
func (p JavaArchive) TryCompare(other any) (bool, int) {
	if other, exists := other.(JavaArchive); exists {
		return true, p.Compare(other)
	}
	return false, 0
}

type unmarshalJavaManifest JavaManifest

type legacyJavaManifest struct {
	Main          map[string]string            `json:"main"`
	NamedSections map[string]map[string]string `json:"namedSections"`
}

func (m *JavaManifest) UnmarshalJSON(b []byte) error {
	var either map[string]any
	err := json.Unmarshal(b, &either)
	if err != nil {
		return fmt.Errorf("could not unmarshal java manifest: %w", err)
	}
	if _, ok := either["namedSections"]; ok {
		var lm legacyJavaManifest
		if err = json.Unmarshal(b, &lm); err != nil {
			return fmt.Errorf("could not unmarshal java manifest: %w", err)
		}
		*m = lm.toNewManifest()
		return nil
	}
	var jm unmarshalJavaManifest
	err = json.Unmarshal(b, &jm)
	if err != nil {
		return fmt.Errorf("could not unmarshal java manifest: %w", err)
	}
	*m = JavaManifest(jm)
	return nil
}

func (lm legacyJavaManifest) toNewManifest() JavaManifest {
	var result JavaManifest
	result.Main = keyValuesFromMap(lm.Main)
	var sectionNames []string
	for k := range lm.NamedSections {
		sectionNames = append(sectionNames, k)
	}
	stdSort.Strings(sectionNames)
	var sections []KeyValues
	for _, name := range sectionNames {
		section := KeyValues{
			KeyValue{
				Key:   "Name",
				Value: name,
			},
		}
		section = append(section, keyValuesFromMap(lm.NamedSections[name])...)
		sections = append(sections, section)
	}
	result.Sections = sections
	return result
}

func (m JavaManifest) Section(name string) KeyValues {
	for _, section := range m.Sections {
		if sectionName, ok := section.Get("Name"); ok && sectionName == name {
			return section
		}
	}
	return nil
}
