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
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

const pomXMLGlob = "*pom.xml"

var propertyMatcher = regexp.MustCompile("[$][{][^}]+[}]")

func parserPomXML(_ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	pom, err := decodePomXML(reader)
	if err != nil {
		return nil, nil, err
	}

	var pkgs []pkg.Package
	if pom.Dependencies != nil {
		for _, dep := range *pom.Dependencies {
			p := newPackageFromPom(
				pom,
				dep,
				reader.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
			)
			if p.Name == "" {
				continue
			}

			pkgs = append(pkgs, p)
		}
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
	artifactID := safeString(p.ArtifactID)
	name := safeString(p.Name)
	projectURL := safeString(p.URL)
	return &pkg.PomProject{
		Path:        path,
		Parent:      pomParent(p, p.Parent),
		GroupID:     resolveProperty(p, p.GroupID),
		ArtifactID:  artifactID,
		Version:     resolveProperty(p, p.Version),
		Name:        name,
		Description: cleanDescription(p.Description),
		URL:         projectURL,
	}
}

func newPackageFromPom(pom gopom.Project, dep gopom.Dependency, locations ...file.Location) pkg.Package {
	m := pkg.JavaMetadata{
		PomProperties: &pkg.PomProperties{
			GroupID:    resolveProperty(pom, dep.GroupID),
			ArtifactID: resolveProperty(pom, dep.ArtifactID),
			Scope:      resolveProperty(pom, dep.Scope),
		},
	}

	name := safeString(dep.ArtifactID)
	version := resolveProperty(pom, dep.Version)

	p := pkg.Package{
		Name:         name,
		Version:      version,
		Locations:    file.NewLocationSet(locations...),
		PURL:         packageURL(name, version, m),
		Language:     pkg.Java,
		Type:         pkg.JavaPkg, // TODO: should we differentiate between packages from jar/war/zip versus packages from a pom.xml that were not installed yet?
		MetadataType: pkg.JavaMetadataType,
		Metadata:     m,
	}

	p.SetID()

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

func pomParent(pom gopom.Project, parent *gopom.Parent) (result *pkg.PomParent) {
	if parent == nil {
		return nil
	}

	artifactID := safeString(parent.ArtifactID)
	result = &pkg.PomParent{
		GroupID:    resolveProperty(pom, parent.GroupID),
		ArtifactID: artifactID,
		Version:    resolveProperty(pom, parent.Version),
	}

	if result.GroupID == "" && result.ArtifactID == "" && result.Version == "" {
		return nil
	}
	return result
}

func cleanDescription(original *string) (cleaned string) {
	if original == nil {
		return ""
	}
	descriptionLines := strings.Split(*original, "\n")
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
//
//nolint:gocognit
func resolveProperty(pom gopom.Project, property *string) string {
	propertyCase := safeString(property)
	return propertyMatcher.ReplaceAllStringFunc(propertyCase, func(match string) string {
		propertyName := strings.TrimSpace(match[2 : len(match)-1])
		entries := pomProperties(pom)
		if value, ok := entries[propertyName]; ok {
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
					tag := f.Tag.Get("xml")
					tag = strings.TrimSuffix(tag, ",omitempty")
					if part == tag {
						pomValue = pomValue.Field(fieldNum)
						pomValueType = pomValue.Type()
						if pomValueType.Kind() == reflect.Ptr {
							pomValue = pomValue.Elem()
							pomValueType = pomValue.Type()
						}
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

func pomProperties(p gopom.Project) map[string]string {
	if p.Properties != nil {
		return p.Properties.Entries
	}
	return map[string]string{}
}

func safeString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
