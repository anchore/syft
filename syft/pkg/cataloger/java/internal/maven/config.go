package maven

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/mitchellh/go-homedir"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
)

const mavenBaseURL = "https://repo1.maven.org/maven2"

type Config struct {
	// UseNetwork instructs the maven resolver to use network operations to resolve maven artifacts
	UseNetwork bool `yaml:"use-network" json:"use-network" mapstructure:"use-network"`

	// Repositories are the set of remote repositories the network resolution should use
	Repositories []string `yaml:"maven-repositories" json:"maven-repositories" mapstructure:"maven-repositories"`

	// UseLocalRepository instructs the maven resolver to look in the host maven cache, usually ~/.m2/repository
	UseLocalRepository bool `yaml:"use-maven-local-repository" json:"use-maven-local-repository" mapstructure:"use-maven-local-repository"`

	// LocalRepositoryDir is an alternate directory to use to look up the local repository
	LocalRepositoryDir string `yaml:"maven-local-repository-dir" json:"maven-local-repository-dir" mapstructure:"maven-local-repository-dir"`

	// MaxParentRecursiveDepth allows for a maximum depth to use when recursively resolving parent poms and other information, 0 disables any maximum
	MaxParentRecursiveDepth int `yaml:"max-parent-recursive-depth" json:"max-parent-recursive-depth" mapstructure:"max-parent-recursive-depth"`
}

func DefaultConfig() Config {
	return Config{
		UseNetwork:              false,
		Repositories:            []string{mavenBaseURL},
		UseLocalRepository:      false,
		LocalRepositoryDir:      defaultMavenLocalRepoDir(),
		MaxParentRecursiveDepth: 0, // unlimited
	}
}

// defaultMavenLocalRepoDir gets default location of the Maven local repository, generally at <USER HOME DIR>/.m2/repository
func defaultMavenLocalRepoDir() string {
	homeDir, err := homedir.Dir()
	if err != nil {
		return ""
	}

	mavenHome := filepath.Join(homeDir, ".m2")

	settingsXML := filepath.Join(mavenHome, "settings.xml")
	settings, err := os.Open(settingsXML)
	if err == nil && settings != nil {
		defer internal.CloseAndLogError(settings, settingsXML)
		localRepository := getSettingsXMLLocalRepository(settings)
		if localRepository != "" {
			return localRepository
		}
	}
	return filepath.Join(mavenHome, "repository")
}

// getSettingsXMLLocalRepository reads the provided settings.xml and parses the localRepository, if present
func getSettingsXMLLocalRepository(settingsXML io.Reader) string {
	type settings struct {
		LocalRepository string `xml:"localRepository"`
	}
	s := settings{}
	err := xml.NewDecoder(settingsXML).Decode(&s)
	if err != nil {
		log.WithFields("error", err).Debug("unable to read maven settings.xml")
	}
	return s.LocalRepository
}

// remotePomURL returns a URL to download a POM from a remote repository
func remotePomURL(repoURL, groupID, artifactID, version string) (requestURL string, err error) {
	// groupID needs to go from maven.org -> maven/org
	urlPath := strings.Split(groupID, ".")
	artifactPom := fmt.Sprintf("%s-%s.pom", artifactID, version)
	urlPath = append(urlPath, artifactID, version, artifactPom)

	// ex: https://repo1.maven.org/maven2/groupID/artifactID/artifactPom
	requestURL, err = url.JoinPath(repoURL, urlPath...)
	if err != nil {
		return requestURL, fmt.Errorf("could not construct maven url: %w", err)
	}
	return requestURL, err
}
