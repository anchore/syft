package java

import (
	"context"
	"errors"
	"strings"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/java/internal/maven"
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

	r := maven.NewResolver(fileResolver, p.cfg.mavenConfig())

	poms := map[*maven.Project]file.Location{}
	for _, pomLocation := range locations {
		pom, err := readPomFromLocation(fileResolver, pomLocation)
		if err != nil || pom == nil {
			log.WithFields("error", err, "pomLocation", pomLocation).Debug("error while reading pom")
			continue
		}

		poms[pom] = pomLocation
		r.AddPom(pom, pomLocation)
	}

	var pkgs []pkg.Package
	var relationships []artifact.Relationship
	var errs []error

	for pom, location := range poms {
		mainPkg := newPackageFromMavenPom(ctx, r, pom, location)
		mainPkg.SetID()

		if mainPkg != nil {
			pkgs = append(pkgs, *mainPkg)
		}

		newPkgs, newRelationships, newErrs := collectDependencies(ctx, r, mainPkg, pom, location, p.cfg.IncludeTransitiveDependencies)
		pkgs = append(pkgs, newPkgs...)
		relationships = append(relationships, newRelationships...)
		errs = append(errs, newErrs...)
	}
	return pkgs, relationships, errors.Join(errs...)
}

func readPomFromLocation(fileResolver file.Resolver, pomLocation file.Location) (*maven.Project, error) {
	contents, err := fileResolver.FileContentsByLocation(pomLocation)
	if err != nil {
		return nil, err
	}
	defer internal.CloseAndLogError(contents, pomLocation.RealPath)
	return maven.ParsePomXML(contents)
}

func collectDependencies(ctx context.Context, r *maven.Resolver, parentPkg *pkg.Package, pom *maven.Project, loc file.Location, includeTransitiveDependencies bool) ([]pkg.Package, []artifact.Relationship, []error) {
	var errs []error
	var pkgs []pkg.Package
	var relationships []artifact.Relationship

	pomID := r.ResolveID(ctx, pom)
	for _, dep := range maven.DirectPomDependencies(pom) {
		depID := r.ResolveDependencyID(ctx, pom, dep)
		log.WithFields("pomLocation", loc, "mavenID", pomID, "dependencyID", depID).Trace("adding maven pom dependency")

		p, err := newPackageFromDependency(
			ctx,
			r,
			pom,
			dep,
			loc.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		)
		if err != nil {
			log.WithFields("error", err, "pomLocation", loc, "mavenID", pomID, "dependencyID", depID).Debugf("error adding dependency")
		}
		if p == nil {
			continue
		}
		pkgs = append(pkgs, *p)

		if parentPkg != nil {
			relationships = append(relationships, artifact.Relationship{
				From: *p,
				To:   *parentPkg,
				Type: artifact.DependencyOfRelationship,
			})
		}

		if includeTransitiveDependencies {
			depPom, err := r.FindPom(ctx, depID.GroupID, depID.ArtifactID, depID.Version)
			if err != nil {
				errs = append(errs, err)
			}
			if depPom == nil {
				continue
			}
			transitivePkgs, transitiveRelationships, transitiveErrs := collectDependencies(ctx, r, p, depPom, loc, includeTransitiveDependencies)
			pkgs = append(pkgs, transitivePkgs...)
			relationships = append(relationships, transitiveRelationships...)
			errs = append(errs, transitiveErrs...)
		}
	}

	return pkgs, relationships, errs
}

func newPomProject(ctx context.Context, r *maven.Resolver, path string, pom *maven.Project) *pkg.JavaPomProject {
	id := r.ResolveID(ctx, pom)
	name := r.ResolveProperty(ctx, pom.Name, pom)
	projectURL := r.ResolveProperty(ctx, pom.URL, pom)

	log.WithFields("path", path, "artifactID", id.ArtifactID, "name", name, "projectURL", projectURL).Trace("parsing pom.xml")
	return &pkg.JavaPomProject{
		Path:        path,
		Parent:      pomParent(ctx, r, pom),
		GroupID:     id.GroupID,
		ArtifactID:  id.ArtifactID,
		Version:     id.Version,
		Name:        name,
		Description: cleanDescription(r.ResolveProperty(ctx, pom.Description, pom)),
		URL:         projectURL,
	}
}

func newPackageFromDependency(ctx context.Context, r *maven.Resolver, pom *maven.Project, dep maven.Dependency, locations ...file.Location) (*pkg.Package, error) {
	id := r.ResolveDependencyID(ctx, pom, dep)

	m := pkg.JavaArchive{
		PomProperties: &pkg.JavaPomProperties{
			GroupID:    id.GroupID,
			ArtifactID: id.ArtifactID,
			Scope:      r.ResolveProperty(ctx, dep.Scope, pom),
		},
	}

	var err error
	var licenses []pkg.License
	dependencyPom, depErr := r.FindPom(ctx, id.GroupID, id.ArtifactID, id.Version)
	if depErr != nil {
		err = errors.Join(err, depErr)
	}

	if dependencyPom != nil {
		depLicenses, _ := r.ResolveLicenses(ctx, dependencyPom)
		licenses = append(licenses, toPkgLicenses(nil, depLicenses)...)
	}

	p := &pkg.Package{
		Name:      id.ArtifactID,
		Version:   id.Version,
		Locations: file.NewLocationSet(locations...),
		Licenses:  pkg.NewLicenseSet(licenses...),
		PURL:      packageURL(id.ArtifactID, id.Version, m),
		Language:  pkg.Java,
		Type:      pkg.JavaPkg, // TODO: should we differentiate between packages from jar/war/zip versus packages from a pom.xml that were not installed yet?
		FoundBy:   pomCatalogerName,
		Metadata:  m,
	}

	p.SetID()

	return p, err
}

func pomParent(ctx context.Context, r *maven.Resolver, pom *maven.Project) *pkg.JavaPomParent {
	if pom == nil || pom.Parent == nil {
		return nil
	}

	groupID := r.ResolveProperty(ctx, pom.Parent.GroupID, pom)
	artifactID := r.ResolveProperty(ctx, pom.Parent.ArtifactID, pom)
	version := r.ResolveProperty(ctx, pom.Parent.Version, pom)

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
