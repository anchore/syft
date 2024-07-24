package java

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/saintfish/chardet"
	"github.com/vifraa/gopom"
	"golang.org/x/net/html/charset"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

const (
	pomXMLGlob       = "*pom.xml"
	pomCatalogerName = "java-pom-cataloger"
)

type pomXMLCataloger struct {
	cfg ArchiveCatalogerConfig
}

func (p pomXMLCataloger) Name() string {
	return pomCatalogerName
}

func (p pomXMLCataloger) Catalog(ctx context.Context, fileResolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	locations, err := fileResolver.FilesByGlob("**/pom.xml")
	if err != nil {
		return nil, nil, err
	}

	r := newMavenResolver(fileResolver, p.cfg)

	var poms []*gopom.Project
	for _, pomLocation := range locations {
		pom, err := readPomFromLocation(fileResolver, pomLocation)
		if err != nil || pom == nil {
			log.Debugf("error while getting contents for: %v %v", pomLocation.RealPath, err)
			continue
		}

		poms = append(poms, pom)

		// store information about this pom for future lookups
		r.pomLocations[pom] = pomLocation
		r.resolved[r.resolveMavenID(ctx, pom)] = pom
	}

	var pkgs []pkg.Package
	for _, pom := range poms {
		pkgs = append(pkgs, processPomXML(ctx, r, pom, r.pomLocations[pom])...)
	}
	return pkgs, nil, nil
}

func readPomFromLocation(fileResolver file.Resolver, pomLocation file.Location) (*gopom.Project, error) {
	contents, err := fileResolver.FileContentsByLocation(pomLocation)
	if err != nil {
		return nil, err
	}
	defer internal.CloseAndLogError(contents, pomLocation.RealPath)
	return decodePomXML(contents)
}

func processPomXML(ctx context.Context, r *mavenResolver, pom *gopom.Project, loc file.Location) []pkg.Package {
	var pkgs []pkg.Package

	for _, dep := range pomDependencies(pom) {
		id := mavenID{
			r.getPropertyValue(ctx, dep.GroupID, pom),
			r.getPropertyValue(ctx, dep.ArtifactID, pom),
			r.getPropertyValue(ctx, dep.Version, pom),
		}
		log.Tracef("adding dependency to SBOM: %v from: %v", id, r.resolveMavenID(ctx, pom))
		p, err := newPackageFromDependency(
			ctx,
			r,
			pom,
			dep,
			loc.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		)
		if err != nil {
			log.Debugf("error adding dependency %v: %v", id, err)
		}
		if p == nil {
			continue
		}
		pkgs = append(pkgs, *p)
	}

	return pkgs
}

func newPomProject(ctx context.Context, r *mavenResolver, path string, pom *gopom.Project) *pkg.JavaPomProject {
	id := r.resolveMavenID(ctx, pom)
	name := r.getPropertyValue(ctx, pom.Name, pom)
	projectURL := r.getPropertyValue(ctx, pom.URL, pom)

	log.WithFields("path", path, "artifactID", id.ArtifactID, "name", name, "projectURL", projectURL).Trace("parsing pom.xml")
	return &pkg.JavaPomProject{
		Path:        path,
		Parent:      pomParent(ctx, r, pom),
		GroupID:     id.GroupID,
		ArtifactID:  id.ArtifactID,
		Version:     id.Version,
		Name:        name,
		Description: cleanDescription(r.getPropertyValue(ctx, pom.Description, pom)),
		URL:         projectURL,
	}
}

func newPackageFromDependency(ctx context.Context, r *mavenResolver, pom *gopom.Project, dep gopom.Dependency, locations ...file.Location) (*pkg.Package, error) {
	groupID := r.getPropertyValue(ctx, dep.GroupID, pom)
	artifactID := r.getPropertyValue(ctx, dep.ArtifactID, pom)
	version := r.getPropertyValue(ctx, dep.Version, pom)

	var err error
	if version == "" {
		version, err = r.findInheritedVersion(ctx, pom, groupID, artifactID)
	}

	m := pkg.JavaArchive{
		PomProperties: &pkg.JavaPomProperties{
			GroupID:    groupID,
			ArtifactID: artifactID,
			Scope:      r.getPropertyValue(ctx, dep.Scope, pom),
		},
	}

	var licenses []pkg.License
	dependencyPom, depErr := r.findPom(ctx, groupID, artifactID, version)
	if depErr != nil {
		log.Debugf("error getting licenses for %s: %v", mavenID{groupID, artifactID, version}, err)
		err = errors.Join(err, depErr)
	}
	if dependencyPom != nil {
		depLicenses, _ := r.resolveLicenses(ctx, dependencyPom)
		for _, license := range depLicenses {
			licenses = append(licenses, pkg.NewLicenseFromFields(deref(license.Name), deref(license.URL), nil))
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
		FoundBy:   pomCatalogerName,
		Metadata:  m,
	}

	p.SetID()

	return p, err
}

// decodePomXML decodes a pom XML file, detecting and converting non-UTF-8 charsets. this DOES NOT perform any logic to resolve properties such as groupID, artifactID, and version
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

func pomParent(ctx context.Context, r *mavenResolver, pom *gopom.Project) *pkg.JavaPomParent {
	if pom == nil || pom.Parent == nil {
		return nil
	}

	groupID := r.getPropertyValue(ctx, pom.Parent.GroupID, pom)
	artifactID := r.getPropertyValue(ctx, pom.Parent.ArtifactID, pom)
	version := r.getPropertyValue(ctx, pom.Parent.Version, pom)

	if groupID == "" && artifactID == "" && version == "" {
		return nil
	}

	return &pkg.JavaPomParent{
		GroupID:    groupID,
		ArtifactID: artifactID,
		Version:    version,
	}
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
