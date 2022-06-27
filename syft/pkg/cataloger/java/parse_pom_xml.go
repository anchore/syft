package java

import (
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/vifraa/gopom"
	"golang.org/x/net/html/charset"
)

const pomXMLGlob = "*pom.xml"
const pomXMLDirGlob = "**/pom.xml"

func parserPomXML(path string, content io.Reader) ([]*pkg.Package, []artifact.Relationship, error) {
	pom, err := decodePomXML(content)
	if err != nil {
		return nil, nil, err
	}

	var pkgs []*pkg.Package
	for _, dep := range pom.Dependencies {
		p := newPackageFromPom(dep)
		if p.Name == "" {
			continue
		}

		pkgs = append(pkgs, p)
	}

	return pkgs, nil, nil
}

func parsePomXMLProject(path string, reader io.Reader) (*pkg.PomProject, error) {
	project, err := decodePomXML(reader)
	if err != nil {
		return nil, err
	}
	return newPomProject(path, project), nil
}

func newPomProject(path string, p gopom.Project) *pkg.PomProject {
	return &pkg.PomProject{
		Path:        path,
		Parent:      pomParent(p.Parent),
		GroupID:     p.GroupID,
		ArtifactID:  p.ArtifactID,
		Version:     p.Version,
		Name:        p.Name,
		Description: cleanDescription(p.Description),
		URL:         p.URL,
	}
}

func newPackageFromPom(dep gopom.Dependency) *pkg.Package {
	p := &pkg.Package{
		Name:         dep.ArtifactID,
		Version:      dep.Version,
		Language:     pkg.Java,
		Type:         pkg.JavaPkg, // TODO: should we differentiate between packages from jar/war/zip versus packages from a pom.xml that were not installed yet?
		MetadataType: pkg.JavaMetadataType,
		FoundBy:      javaPomCataloger,
	}

	p.Metadata = pkg.JavaMetadata{PURL: packageURL(*p)}

	return p
}

func decodePomXML(content io.Reader) (project gopom.Project, err error) {
	decoder := xml.NewDecoder(content)
	// prevent against warnings for "xml: encoding "iso-8859-1" declared but Decoder.CharsetReader is nil"
	decoder.CharsetReader = charset.NewReaderLabel
	if err := decoder.Decode(&project); err != nil {
		return project, fmt.Errorf("unable to unmarshal pom.xml: %w", err)
	}

	return project, nil
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
