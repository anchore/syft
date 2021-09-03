package java

import (
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	"github.com/anchore/syft/syft/pkg"
	"github.com/vifraa/gopom"
	"golang.org/x/net/html/charset"
)

const pomXMLGlob = "*pom.xml"

func parsePomXML(path string, reader io.Reader) (*pkg.PomProject, error) {
	var project gopom.Project

	decoder := xml.NewDecoder(reader)
	// prevent against warnings for "xml: encoding "iso-8859-1" declared but Decoder.CharsetReader is nil"
	decoder.CharsetReader = charset.NewReaderLabel

	if err := decoder.Decode(&project); err != nil {
		return nil, fmt.Errorf("unable to unmarshal pom.xml: %w", err)
	}

	return &pkg.PomProject{
		Path:        path,
		Parent:      pomParent(project.Parent),
		GroupID:     project.GroupID,
		ArtifactID:  project.ArtifactID,
		Version:     project.Version,
		Name:        project.Name,
		Description: cleanDescription(project.Description),
		URL:         project.URL,
	}, nil
}

func pomParent(parent gopom.Parent) (result *pkg.PomParent) {
	if parent.ArtifactID != "" || parent.GroupID != "" || parent.Version != "" {
		result = &pkg.PomParent{
			GroupID:    parent.GroupID,
			ArtifactID: parent.ArtifactID,
			Version:    parent.Version,
		}
	}
	return result
}

func cleanDescription(original string) (cleaned string) {
	descriptionLines := strings.Split(original, "\n")
	for _, line := range descriptionLines {
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		cleaned += line + " "
	}
	return strings.TrimSpace(cleaned)
}
