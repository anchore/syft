package java

import (
	"encoding/xml"
	"io"
	"os"
	"path/filepath"

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
		log.Debugf("unable to read maven settings.xml: %v", err)
	}
	return s.LocalRepository
}
