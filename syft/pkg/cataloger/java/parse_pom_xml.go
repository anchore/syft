package java

import (
	"encoding/xml"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strings"

	"github.com/vifraa/gopom"
	"golang.org/x/net/html/charset"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
)

const pomXMLGlob = "*pom.xml"
const pomXMLDirGlob = "**/pom.xml"

var propertyMatcher = regexp.MustCompile("[$][{][^}]+[}]")

func parserPomXML(path string, content io.Reader) ([]*pkg.Package, []artifact.Relationship, error) {
	pom, err := decodePomXML(content)
	if err != nil {
		return nil, nil, err
	}

	var pkgs []*pkg.Package
	for _, dep := range pom.Dependencies {
		p := newPackageFromPom(pom, dep)
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
		Parent:      pomParent(p, p.Parent),
		GroupID:     resolveProperty(p, p.GroupID),
		ArtifactID:  p.ArtifactID,
		Version:     resolveProperty(p, p.Version),
		Name:        p.Name,
		Description: cleanDescription(p.Description),
		URL:         p.URL,
	}
}

func newPackageFromPom(pom gopom.Project, dep gopom.Dependency) *pkg.Package {
	p := &pkg.Package{
		Name:         dep.ArtifactID,
		Version:      resolveProperty(pom, dep.Version),
		Language:     pkg.Java,
		Type:         pkg.JavaPkg, // TODO: should we differentiate between packages from jar/war/zip versus packages from a pom.xml that were not installed yet?
		MetadataType: pkg.JavaMetadataType,
		FoundBy:      javaPomCataloger,
		Metadata: pkg.JavaMetadata{
			PomProperties: &pkg.PomProperties{
				GroupID: resolveProperty(pom, dep.GroupID),
			},
		},
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

func pomParent(pom gopom.Project, parent gopom.Parent) (result *pkg.PomParent) {
	if parent.ArtifactID != "" || parent.GroupID != "" || parent.Version != "" {
		result = &pkg.PomParent{
			GroupID:    resolveProperty(pom, parent.GroupID),
			ArtifactID: parent.ArtifactID,
			Version:    resolveProperty(pom, parent.Version),
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

// resolveProperty emulates some maven property resolution logic by looking in the project's variables
// as well as supporting the project expressions like ${project.parent.groupId}.
// If no match is found, the entire expression including ${} is returned
func resolveProperty(pom gopom.Project, property string) string {
	return propertyMatcher.ReplaceAllStringFunc(property, func(match string) string {
		propertyName := strings.TrimSpace(match[2 : len(match)-1])
		if value, ok := pom.Properties.Entries[propertyName]; ok {
			return value
		}
		// if we don't find anything directly in the pom properties,
		// see if we have a project.x expression and process this based
		// on the xml tags in gopom
		parts := strings.Split(propertyName, ".")
		numParts := len(parts)
		if numParts > 1 && strings.TrimSpace(parts[0]) == "project" {
			pomValue := reflect.ValueOf(pom)
			pomValueType := pomValue.Type()
			for partNum := 1; partNum < numParts; partNum++ {
				if pomValueType.Kind() != reflect.Struct {
					break
				}
				part := parts[partNum]
				for fieldNum := 0; fieldNum < pomValueType.NumField(); fieldNum++ {
					f := pomValueType.Field(fieldNum)
					if part == f.Tag.Get("xml") {
						pomValue = pomValue.Field(fieldNum)
						pomValueType = pomValue.Type()
						if partNum == numParts-1 {
							return fmt.Sprintf("%v", pomValue.Interface())
						}
						break
					}
				}
			}
		}
		return match
	})
}
