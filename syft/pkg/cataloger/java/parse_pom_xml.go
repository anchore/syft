package java

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"github.com/saintfish/chardet"
	"github.com/vifraa/gopom"
	"golang.org/x/net/html/charset"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

const pomXMLGlob = "*pom.xml"

var expressionMatcher = regexp.MustCompile("[$][{][^}]+[}]")

func (gap genericArchiveParserAdapter) parsePomXML(ctx context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	pom, err := decodePomXML(reader)
	if err != nil || pom == nil {
		return nil, nil, err
	}

	r := newMavenResolver(gap.cfg)

	var pkgs []pkg.Package

	for _, dep := range directDependencies(pom) {
		id := newMavenID(dep.GroupID, dep.ArtifactID, dep.Version)
		log.Debugf("add dependency to SBOM : [%v]", id)
		p, err := r.newPackageFromDependency(
			ctx,
			pom,
			dep,
			reader.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		)
		if err != nil {
			log.Debugf("error adding dependency %v: %v", id, err)
		}
		if p == nil {
			continue
		}
		pkgs = append(pkgs, *p)
	}

	return pkgs, nil, nil
}

func parsePomXMLProject(ctx context.Context, path string, reader io.Reader, location file.Location, cfg ArchiveCatalogerConfig) (*parsedPomProject, error) {
	pom, err := decodePomXML(reader)
	if err != nil {
		return nil, err
	}

	resolver := newMavenResolver(cfg)

	return resolver.newPomProject(ctx, path, pom, location), nil
}

func (r *mavenResolver) newPomProject(ctx context.Context, path string, pom *gopom.Project, location file.Location) *parsedPomProject {
	artifactID := deref(pom.ArtifactID)
	name := deref(pom.Name)
	projectURL := deref(pom.URL)

	var licenses []pkg.License
	if pom.Licenses != nil {
		for _, license := range *pom.Licenses {
			var licenseName, licenseURL string
			if license.Name != nil {
				licenseName = *license.Name
			}
			if license.URL != nil {
				licenseURL = *license.URL
			}

			if licenseName == "" && licenseURL == "" {
				continue
			}

			licenses = append(licenses, pkg.NewLicenseFromFields(licenseName, licenseURL, &location))
		}
	}

	log.WithFields("path", path, "artifactID", artifactID, "name", name, "projectURL", projectURL).Trace("parsing pom.xml")
	return &parsedPomProject{
		JavaPomProject: &pkg.JavaPomProject{
			Path:        path,
			Parent:      r.pomParent(ctx, pom),
			GroupID:     r.getPropertyValue(ctx, pom, pom.GroupID),
			ArtifactID:  artifactID,
			Version:     r.getPropertyValue(ctx, pom, pom.Version),
			Name:        name,
			Description: cleanDescription(pom.Description),
			URL:         projectURL,
		},
		Licenses: licenses,
	}
}

func (r *mavenResolver) newPackageFromDependency(ctx context.Context, pom *gopom.Project, dep gopom.Dependency, locations ...file.Location) (*pkg.Package, error) {
	groupID := r.getPropertyValue(ctx, pom, dep.GroupID)
	artifactID := r.getPropertyValue(ctx, pom, dep.ArtifactID)
	version := r.getPropertyValue(ctx, pom, dep.Version)

	var err error
	if version == "" {
		version, err = r.findInheritedVersion(ctx, pom, pom, groupID, artifactID)
	}

	m := pkg.JavaArchive{
		PomProperties: &pkg.JavaPomProperties{
			GroupID:    groupID,
			ArtifactID: artifactID,
			Scope:      r.getPropertyValue(ctx, pom, dep.Scope),
		},
	}

	licenses := make([]pkg.License, 0)
	if version == "" {
		dependencyPom, depErr := r.findPom(ctx, groupID, artifactID, version)
		if depErr != nil {
			log.Debugf("error getting licenses for %s: %v", mavenID{groupID, artifactID, version}, err)
			err = errors.Join(err, depErr)
		}
		if dependencyPom != nil {
			parentLicenses, _ := r.findLicenses(ctx, dependencyPom)
			for _, licenseName := range parentLicenses {
				licenses = append(licenses, pkg.NewLicenseFromFields(licenseName, "", nil))
			}
		}
	}

	p := &pkg.Package{
		Name:      artifactID,
		Version:   version,
		Locations: file.NewLocationSet(locations...),
		Licenses:  pkg.NewLicenseSet(licenses...),
		PURL:      packageURL(artifactID, version, m),
		Language:  pkg.Java,
		Type:      pkg.JavaPkg, // TODO: should we differentiate between packages from jar/war/zip versus packages from a pom.xml that were not installed yet?
		Metadata:  m,
	}

	p.SetID()

	return p, err
}

func decodePomXML(content io.Reader) (project *gopom.Project, err error) {
	inputReader, err := getUtf8Reader(content)
	if err != nil {
		return nil, fmt.Errorf("unable to read pom.xml: %w", err)
	}

	decoder := xml.NewDecoder(inputReader)
	// when an xml file has a character set declaration (e.g. '<?xml version="1.0" encoding="ISO-8859-1"?>') read that and use the correct decoder
	decoder.CharsetReader = charset.NewReaderLabel

	project = &gopom.Project{}
	if err := decoder.Decode(project); err != nil {
		return nil, fmt.Errorf("unable to unmarshal pom.xml: %w", err)
	}

	// For modules groupID and version are almost always inherited from parent pom
	if project.GroupID == nil && project.Parent != nil {
		project.GroupID = project.Parent.GroupID
	}
	if project.Version == nil && project.Parent != nil {
		project.Version = project.Parent.Version
	}

	return project, nil
}

func getUtf8Reader(content io.Reader) (io.Reader, error) {
	pomContents, err := io.ReadAll(content)
	if err != nil {
		return nil, err
	}

	detector := chardet.NewTextDetector()
	detection, err := detector.DetectBest(pomContents)

	var inputReader io.Reader
	if err == nil && detection != nil {
		if detection.Charset == "UTF-8" {
			inputReader = bytes.NewReader(pomContents)
		} else {
			inputReader, err = charset.NewReaderLabel(detection.Charset, bytes.NewReader(pomContents))
			if err != nil {
				return nil, fmt.Errorf("unable to get encoding: %w", err)
			}
		}
	} else {
		// we could not detect the encoding, but we want a valid file to read. Replace unreadable
		// characters with the UTF-8 replacement character.
		inputReader = strings.NewReader(strings.ToValidUTF8(string(pomContents), "�"))
	}
	return inputReader, nil
}

func (r *mavenResolver) pomParent(ctx context.Context, pom *gopom.Project) *pkg.JavaPomParent {
	if pom == nil || pom.Parent == nil {
		return nil
	}

	groupID := deref(pom.Parent.GroupID)
	artifactID := deref(pom.Parent.ArtifactID)
	version := deref(pom.Parent.Version)
	if groupID == "" && artifactID == "" && version == "" {
		return nil
	}

	return &pkg.JavaPomParent{
		GroupID:    r.getPropertyValue(ctx, pom, pom.Parent.GroupID),
		ArtifactID: artifactID,
		Version:    r.getPropertyValue(ctx, pom, pom.Parent.Version),
	}
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

// getPropertyValue gets property values by emulating maven property resolution logic, looking in the project's variables
// as well as supporting the project expressions like ${project.parent.groupId}.
// Properties which are not resolved result in empty string ""
//
//nolint:gocognit
func (r *mavenResolver) getPropertyValue(ctx context.Context, pom *gopom.Project, propertyValue *string) string {
	if propertyValue == nil {
		return ""
	}
	resolved, err := r.resolveExpression(ctx, pom, *propertyValue, nil)
	if err != nil {
		log.Debugf("error resolving maven property: %s: %v", *propertyValue, err)
		return ""
	}
	return resolved
}

// resolveExpression resolves an expression, which may be a plain string or a string with ${ property.references }
//
//nolint:gocognit
func (r *mavenResolver) resolveExpression(ctx context.Context, pom *gopom.Project, expression string, resolving []string) (string, error) {
	var err error
	return expressionMatcher.ReplaceAllStringFunc(expression, func(match string) string {
		propertyExpression := strings.TrimSpace(match[2 : len(match)-1]) // remove leading ${ and trailing }
		resolved, e := r.resolveProperty(ctx, pom, propertyExpression, resolving)
		if e != nil {
			err = errors.Join(err, e)
			return ""
		}
		return resolved
	}), err
}

// resolveProperty resolves properties recursively from the root project
//
//nolint:gocognit
func (r *mavenResolver) resolveProperty(ctx context.Context, pom *gopom.Project, propertyExpression string, resolving []string) (string, error) {
	// prevent cycles
	if slices.Contains(resolving, propertyExpression) {
		return "", fmt.Errorf("cycle detected resolving: %s", propertyExpression)
	}
	resolving = append(resolving, propertyExpression)

	value, err := r.resolveProjectProperty(ctx, pom, propertyExpression, resolving)
	if err != nil {
		return value, err
	}
	if value != "" {
		return value, nil
	}

	current := pom
	for current != nil {
		if current.Properties != nil && current.Properties.Entries != nil {
			if value, ok := current.Properties.Entries[propertyExpression]; ok {
				return r.resolveExpression(ctx, pom, value, resolving) // property values can contain expressions
			}
		}
		current, err = r.findParent(ctx, current)
		if err != nil {
			return "", err
		}
	}

	return "", fmt.Errorf("unable to resolve property: %s", propertyExpression)
}

// resolveProjectProperty resolves properties on the project
//
//nolint:gocognit
func (r *mavenResolver) resolveProjectProperty(ctx context.Context, pom *gopom.Project, propertyExpression string, resolving []string) (string, error) {
	// see if we have a project.x expression and process this based
	// on the xml tags in gopom
	parts := strings.Split(propertyExpression, ".")
	numParts := len(parts)
	if numParts > 1 && strings.TrimSpace(parts[0]) == "project" {
		pomValue := reflect.ValueOf(pom).Elem()
		pomValueType := pomValue.Type()
		for partNum := 1; partNum < numParts; partNum++ {
			if pomValueType.Kind() != reflect.Struct {
				break
			}

			part := parts[partNum]
			for fieldNum := 0; fieldNum < pomValueType.NumField(); fieldNum++ {
				f := pomValueType.Field(fieldNum)
				tag := f.Tag.Get("xml")
				tag = strings.Split(tag, ",")[0]
				// a segment of the property name matches the xml tag for the field,
				// so we need to recurse down the nested structs or return a match
				// if we're done.
				if part != tag {
					continue
				}

				pomValue = pomValue.Field(fieldNum)
				pomValueType = pomValue.Type()
				if pomValueType.Kind() == reflect.Ptr {
					// we were recursing down the nested structs, but one of the steps
					// we need to take is a nil pointer, so give up
					if pomValue.IsNil() {
						return "", fmt.Errorf("property undefined: %s", propertyExpression)
					}
					pomValue = pomValue.Elem()
					if !pomValue.IsZero() {
						// we found a non-zero value whose tag matches this part of the property name
						pomValueType = pomValue.Type()
					}
				}
				// If this was the last part of the property name, return the value
				if partNum == numParts-1 {
					value := fmt.Sprintf("%v", pomValue.Interface())
					return r.resolveExpression(ctx, pom, value, resolving)
				}
				break
			}
		}
	}
	return "", nil
}

// func pomProperties(p gopom.Project) map[string]string {
//	if p.Properties != nil {
//		return p.Properties.Entries
//	}
//	return map[string]string{}
//}

// func deref(s *string) string {
//	if s == nil {
//		return ""
//	}
//	return *s
//}
