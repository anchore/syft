package java

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

// deref dereferences ptr if not nil, or returns the type default value if ptr is nil
func deref[T any](ptr *T) T {
	if ptr == nil {
		var t T
		return t
	}
	return *ptr
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
