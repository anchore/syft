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

	var parent *pkg.PomParent
	if project.Parent.ArtifactID != "" || project.Parent.GroupID != "" || project.Parent.Version != "" {
		parent = &pkg.PomParent{
			GroupID:    project.Parent.GroupID,
			ArtifactID: project.Parent.ArtifactID,
			Version:    project.Parent.Version,
		}
	}

	var description string
	descriptionLines := strings.Split(project.Description, "\n")
	for _, line := range descriptionLines {
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		description += line + " "
	}
	description = strings.TrimSpace(description)

	return &pkg.PomProject{
		Path:        path,
		Parent:      parent,
		GroupID:     project.GroupID,
		ArtifactID:  project.ArtifactID,
		Version:     project.Version,
		Name:        project.Name,
		Description: description,
		URL:         project.URL,
	}, nil
}
