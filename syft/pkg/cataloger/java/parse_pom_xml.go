package java

import (
	"context"
	"errors"
	"strings"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/unknown"
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

	var errs error
	var poms []*maven.Project
	pomLocations := map[*maven.Project]file.Location{}
	for _, pomLocation := range locations {
		pom, err := readPomFromLocation(fileResolver, pomLocation)
		if err != nil || pom == nil {
			log.WithFields("error", err, "pomLocation", pomLocation).Debug("error while reading pom")
			errs = unknown.Appendf(errs, pomLocation, "error reading pom.xml: %w", err)
			continue
		}

		poms = append(poms, pom)
		pomLocations[pom] = pomLocation
		r.AddPom(ctx, pom, pomLocation)
	}

	var pkgs []pkg.Package
	var relationships []artifact.Relationship
	resolved := map[maven.ID]*pkg.Package{}

	// catalog all the main packages first so these can be referenced later when building the dependency graph
	for _, pom := range poms {
		location := pomLocations[pom] // should always exist

		id := r.ResolveID(ctx, pom)
		mainPkg := newPackageFromMavenPom(ctx, r, pom, location)
		if mainPkg == nil {
			continue
		}
		resolved[id] = mainPkg
		pkgs = append(pkgs, *mainPkg)
	}

	// catalog all dependencies
	for _, pom := range poms {
		location := pomLocations[pom] // should always exist

		id := r.ResolveID(ctx, pom)
		mainPkg := resolved[id]

		newPkgs, newRelationships, newErrs := collectDependencies(ctx, r, resolved, mainPkg, pom, location, p.cfg.ResolveTransitiveDependencies)
		pkgs = append(pkgs, newPkgs...)
		relationships = append(relationships, newRelationships...)
		errs = unknown.Join(errs, newErrs)
	}

	return pkgs, relationships, errs
}

func readPomFromLocation(fileResolver file.Resolver, pomLocation file.Location) (*maven.Project, error) {
	contents, err := fileResolver.FileContentsByLocation(pomLocation)
	if err != nil {
		return nil, err
	}
	defer internal.CloseAndLogError(contents, pomLocation.RealPath)
	return maven.ParsePomXML(contents)
}

// newPackageFromMavenPom processes a single Maven POM for a given parent package, returning only the main package from the pom
func newPackageFromMavenPom(ctx context.Context, r *maven.Resolver, pom *maven.Project, location file.Location) *pkg.Package {
	id := r.ResolveID(ctx, pom)
	parent, err := r.ResolveParent(ctx, pom)
	if err != nil {
		// this is expected in many cases, there will be no network access and the maven resolver is unable to
		// look up information, so we can continue with what little information we have
		log.Trace("unable to resolve parent due to: %v", err)
	}

	var javaPomParent *pkg.JavaPomParent
	if parent != nil { // parent is returned in both cases: when it is resolved or synthesized from the pom.parent info
		parentID := r.ResolveID(ctx, parent)
		javaPomParent = &pkg.JavaPomParent{
			GroupID:    parentID.GroupID,
			ArtifactID: parentID.ArtifactID,
			Version:    parentID.Version,
		}
	}

	pomLicenses, err := r.ResolveLicenses(ctx, pom)
	if err != nil {
		log.Tracef("error resolving licenses: %v", err)
	}
	licenses := toPkgLicenses(&location, pomLicenses)

	m := pkg.JavaArchive{
		PomProject: &pkg.JavaPomProject{
			Parent:      javaPomParent,
			GroupID:     id.GroupID,
			ArtifactID:  id.ArtifactID,
			Version:     id.Version,
			Name:        r.ResolveProperty(ctx, pom, pom.Name),
			Description: r.ResolveProperty(ctx, pom, pom.Description),
			URL:         r.ResolveProperty(ctx, pom, pom.URL),
		},
	}

	p := &pkg.Package{
		Name:    id.ArtifactID,
		Version: id.Version,
		Locations: file.NewLocationSet(
			location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		),
		Licenses: pkg.NewLicenseSet(licenses...),
		Language: pkg.Java,
		Type:     pkg.JavaPkg,
		FoundBy:  pomCatalogerName,
		PURL:     packageURL(id.ArtifactID, id.Version, m),
		Metadata: m,
	}

	finalizePackage(p)

	return p
}

func collectDependencies(ctx context.Context, r *maven.Resolver, resolved map[maven.ID]*pkg.Package, parentPkg *pkg.Package, pom *maven.Project, loc file.Location, includeTransitiveDependencies bool) ([]pkg.Package, []artifact.Relationship, error) {
	var errs error
	var pkgs []pkg.Package
	var relationships []artifact.Relationship

	pomID := r.ResolveID(ctx, pom)
	for _, dep := range maven.DirectPomDependencies(pom) {
		depID := r.ResolveDependencyID(ctx, pom, dep)
		log.WithFields("pomLocation", loc, "mavenID", pomID, "dependencyID", depID).Trace("adding maven pom dependency")

		// we may have a reference to a package pointing to an existing pom on the filesystem, but we don't want to duplicate these entries
		depPkg := resolved[depID]
		if depPkg == nil {
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
				// we don't have a valid package, just continue to the next dependency
				continue
			}
			depPkg = p
			resolved[depID] = depPkg

			// only resolve transitive dependencies if we're not already looking these up for the specific package
			if includeTransitiveDependencies && depID.Valid() {
				depPom, err := r.FindPom(ctx, depID.GroupID, depID.ArtifactID, depID.Version)
				if err != nil {
					log.WithFields("mavenID", depID, "error", err).Debug("error finding pom")
				}
				if depPom != nil {
					transitivePkgs, transitiveRelationships, transitiveErrs := collectDependencies(ctx, r, resolved, depPkg, depPom, loc, includeTransitiveDependencies)
					pkgs = append(pkgs, transitivePkgs...)
					relationships = append(relationships, transitiveRelationships...)
					errs = unknown.Join(errs, transitiveErrs)
				}
			}
		}

		pkgs = append(pkgs, *depPkg)
		if parentPkg != nil {
			relationships = append(relationships, artifact.Relationship{
				From: *depPkg,
				To:   *parentPkg,
				Type: artifact.DependencyOfRelationship,
			})
		}
	}

	return pkgs, relationships, errs
}

func newPomProject(ctx context.Context, r *maven.Resolver, path string, pom *maven.Project) *pkg.JavaPomProject {
	id := r.ResolveID(ctx, pom)
	name := r.ResolveProperty(ctx, pom, pom.Name)
	projectURL := r.ResolveProperty(ctx, pom, pom.URL)

	log.WithFields("path", path, "artifactID", id.ArtifactID, "name", name, "projectURL", projectURL).Trace("parsing pom.xml")
	return &pkg.JavaPomProject{
		Path:        path,
		Parent:      pomParent(ctx, r, pom),
		GroupID:     id.GroupID,
		ArtifactID:  id.ArtifactID,
		Version:     id.Version,
		Name:        name,
		Description: cleanDescription(r.ResolveProperty(ctx, pom, pom.Description)),
		URL:         projectURL,
	}
}

func newPackageFromDependency(ctx context.Context, r *maven.Resolver, pom *maven.Project, dep maven.Dependency, locations ...file.Location) (*pkg.Package, error) {
	id := r.ResolveDependencyID(ctx, pom, dep)

	var err error
	var licenses []pkg.License
	dependencyPom, depErr := r.FindPom(ctx, id.GroupID, id.ArtifactID, id.Version)
	if depErr != nil {
		err = errors.Join(err, depErr)
	}

	var pomProject *pkg.JavaPomProject
	if dependencyPom != nil {
		depLicenses, _ := r.ResolveLicenses(ctx, dependencyPom)
		licenses = append(licenses, toPkgLicenses(nil, depLicenses)...)
		pomProject = &pkg.JavaPomProject{
			Parent:      pomParent(ctx, r, dependencyPom),
			GroupID:     id.GroupID,
			ArtifactID:  id.ArtifactID,
			Version:     id.Version,
			Name:        r.ResolveProperty(ctx, pom, pom.Name),
			Description: r.ResolveProperty(ctx, pom, pom.Description),
			URL:         r.ResolveProperty(ctx, pom, pom.URL),
		}
	}

	m := pkg.JavaArchive{
		PomProperties: &pkg.JavaPomProperties{
			GroupID:    id.GroupID,
			ArtifactID: id.ArtifactID,
			Scope:      r.ResolveProperty(ctx, pom, dep.Scope),
		},
		PomProject: pomProject,
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

	finalizePackage(p)

	return p, err
}

func pomParent(ctx context.Context, r *maven.Resolver, pom *maven.Project) *pkg.JavaPomParent {
	if pom == nil || pom.Parent == nil {
		return nil
	}

	groupID := r.ResolveProperty(ctx, pom, pom.Parent.GroupID)
	artifactID := r.ResolveProperty(ctx, pom, pom.Parent.ArtifactID)
	version := r.ResolveProperty(ctx, pom, pom.Parent.Version)

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
