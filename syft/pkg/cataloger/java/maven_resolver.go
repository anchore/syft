package java

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/vifraa/gopom"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/cache"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
)

// mavenID is the unique identifier for a package in Maven
type mavenID struct {
	GroupID    string
	ArtifactID string
	Version    string
}

func (m mavenID) String() string {
	return fmt.Sprintf("(groupId: %s artifactId: %s version: %s)", m.GroupID, m.ArtifactID, m.Version)
}

var expressionMatcher = regexp.MustCompile("[$][{][^}]+[}]")

// mavenResolver is a short-lived utility to resolve maven poms from multiple sources, including:
// the scanned filesystem, local maven cache directories, remote maven repositories, and the syft cache
type mavenResolver struct {
	cfg                  ArchiveCatalogerConfig
	cache                cache.Cache
	resolved             map[mavenID]*gopom.Project
	remoteRequestTimeout time.Duration
	checkedLocalRepo     bool
	// fileResolver and pomLocations are used to resolve parent poms by relativePath
	fileResolver file.Resolver
	pomLocations map[*gopom.Project]file.Location
}

// newMavenResolver constructs a new mavenResolver with the given configuration.
// NOTE: the fileResolver is optional and if provided will be used to resolve parent poms by relative path
func newMavenResolver(fileResolver file.Resolver, cfg ArchiveCatalogerConfig) *mavenResolver {
	return &mavenResolver{
		cfg:                  cfg,
		cache:                cache.GetManager().GetCache("java/maven/repo", "v1"),
		resolved:             map[mavenID]*gopom.Project{},
		remoteRequestTimeout: time.Second * 10,
		fileResolver:         fileResolver,
		pomLocations:         map[*gopom.Project]file.Location{},
	}
}

// getPropertyValue gets property values by emulating maven property resolution logic, looking in the project's variables
// as well as supporting the project expressions like ${project.parent.groupId}.
// Properties which are not resolved result in empty string ""
func (r *mavenResolver) getPropertyValue(ctx context.Context, propertyValue *string, resolutionContext ...*gopom.Project) string {
	if propertyValue == nil {
		return ""
	}
	resolved, err := r.resolveExpression(ctx, resolutionContext, *propertyValue, nil)
	if err != nil {
		log.WithFields("error", err, "propertyValue", *propertyValue).Debug("error resolving maven property")
		return ""
	}
	return resolved
}

// resolveExpression resolves an expression, which may be a plain string or a string with ${ property.references }
func (r *mavenResolver) resolveExpression(ctx context.Context, resolutionContext []*gopom.Project, expression string, resolving []string) (string, error) {
	var err error
	return expressionMatcher.ReplaceAllStringFunc(expression, func(match string) string {
		propertyExpression := strings.TrimSpace(match[2 : len(match)-1]) // remove leading ${ and trailing }
		resolved, e := r.resolveProperty(ctx, resolutionContext, propertyExpression, resolving)
		if e != nil {
			err = errors.Join(err, e)
			return ""
		}
		return resolved
	}), err
}

// resolveProperty resolves properties recursively from the root project
func (r *mavenResolver) resolveProperty(ctx context.Context, resolutionContext []*gopom.Project, propertyExpression string, resolving []string) (string, error) {
	// prevent cycles
	if slices.Contains(resolving, propertyExpression) {
		return "", fmt.Errorf("cycle detected resolving: %s", propertyExpression)
	}
	if len(resolutionContext) == 0 {
		return "", fmt.Errorf("no project variable resolution context provided for expression: '%s'", propertyExpression)
	}
	resolving = append(resolving, propertyExpression)

	// only resolve project. properties in the context of the current project pom
	value, err := r.resolveProjectProperty(ctx, resolutionContext, resolutionContext[len(resolutionContext)-1], propertyExpression, resolving)
	if err != nil {
		return value, err
	}
	if value != "" {
		return value, nil
	}

	for _, pom := range resolutionContext {
		current := pom
		for parentDepth := 0; current != nil; parentDepth++ {
			if r.cfg.MaxParentRecursiveDepth > 0 && parentDepth > r.cfg.MaxParentRecursiveDepth {
				return "", fmt.Errorf("maximum parent recursive depth (%v) reached resolving property: %v", r.cfg.MaxParentRecursiveDepth, propertyExpression)
			}
			if current.Properties != nil && current.Properties.Entries != nil {
				if value, ok := current.Properties.Entries[propertyExpression]; ok {
					return r.resolveExpression(ctx, resolutionContext, value, resolving) // property values can contain expressions
				}
			}
			current, err = r.resolveParent(ctx, current)
			if err != nil {
				return "", err
			}
		}
	}

	return "", fmt.Errorf("unable to resolve property: %s", propertyExpression)
}

// resolveProjectProperty resolves properties on the project
//
//nolint:gocognit
func (r *mavenResolver) resolveProjectProperty(ctx context.Context, resolutionContext []*gopom.Project, pom *gopom.Project, propertyExpression string, resolving []string) (string, error) {
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
			// these two fields are directly inherited from the pom parent values
			if partNum == 1 && pom.Parent != nil {
				switch part {
				case "version":
					if pom.Version == nil && pom.Parent.Version != nil {
						return r.resolveExpression(ctx, resolutionContext, *pom.Parent.Version, resolving)
					}
				case "groupID":
					if pom.GroupID == nil && pom.Parent.GroupID != nil {
						return r.resolveExpression(ctx, resolutionContext, *pom.Parent.GroupID, resolving)
					}
				}
			}
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
					return r.resolveExpression(ctx, resolutionContext, value, resolving)
				}
				break
			}
		}
	}
	return "", nil
}

// resolveMavenID creates a new mavenID from a pom, resolving parent information as necessary
func (r *mavenResolver) resolveMavenID(ctx context.Context, pom *gopom.Project) mavenID {
	if pom == nil {
		return mavenID{}
	}
	groupID := r.getPropertyValue(ctx, pom.GroupID, pom)
	artifactID := r.getPropertyValue(ctx, pom.ArtifactID, pom)
	version := r.getPropertyValue(ctx, pom.Version, pom)
	if pom.Parent != nil {
		if groupID == "" {
			groupID = r.getPropertyValue(ctx, pom.Parent.GroupID, pom)
		}
		if artifactID == "" {
			artifactID = r.getPropertyValue(ctx, pom.Parent.ArtifactID, pom)
		}
		if version == "" {
			version = r.getPropertyValue(ctx, pom.Parent.Version, pom)
		}
	}
	return mavenID{groupID, artifactID, version}
}

// resolveDependencyID creates a new mavenID from a dependency element in a pom, resolving information as necessary
func (r *mavenResolver) resolveDependencyID(ctx context.Context, pom *gopom.Project, dep gopom.Dependency) mavenID {
	if pom == nil {
		return mavenID{}
	}

	groupID := r.getPropertyValue(ctx, dep.GroupID, pom)
	artifactID := r.getPropertyValue(ctx, dep.ArtifactID, pom)
	version := r.getPropertyValue(ctx, dep.Version, pom)

	var err error
	if version == "" {
		version, err = r.findInheritedVersion(ctx, pom, groupID, artifactID)
	}

	depID := mavenID{groupID, artifactID, version}

	if err != nil {
		log.WithFields("error", err, "mavenID", r.resolveMavenID(ctx, pom), "dependencyID", depID)
	}

	return depID
}

// findPom gets a pom from cache, local repository, or from a remote Maven repository depending on configuration
func (r *mavenResolver) findPom(ctx context.Context, groupID, artifactID, version string) (*gopom.Project, error) {
	if groupID == "" || artifactID == "" || version == "" {
		return nil, fmt.Errorf("invalid maven pom specification, require non-empty values for groupID: '%s', artifactID: '%s', version: '%s'", groupID, artifactID, version)
	}

	id := mavenID{groupID, artifactID, version}
	pom := r.resolved[id]

	if pom != nil {
		return pom, nil
	}

	var errs error

	// try to resolve first from local maven repo
	if r.cfg.UseMavenLocalRepository {
		pom, err := r.findPomInLocalRepository(groupID, artifactID, version)
		if pom != nil {
			r.resolved[id] = pom
			return pom, nil
		}
		errs = errors.Join(errs, err)
	}

	// resolve via network maven repository
	if pom == nil && r.cfg.UseNetwork {
		pom, err := r.findPomInRemoteRepository(ctx, groupID, artifactID, version)
		if pom != nil {
			r.resolved[id] = pom
			return pom, nil
		}
		errs = errors.Join(errs, err)
	}

	return nil, fmt.Errorf("unable to resolve pom %s %s %s: %w", groupID, artifactID, version, errs)
}

// findPomInLocalRepository attempts to get the POM from the users local maven repository
func (r *mavenResolver) findPomInLocalRepository(groupID, artifactID, version string) (*gopom.Project, error) {
	groupPath := filepath.Join(strings.Split(groupID, ".")...)
	pomFilePath := filepath.Join(r.cfg.MavenLocalRepositoryDir, groupPath, artifactID, version, artifactID+"-"+version+".pom")
	pomFile, err := os.Open(pomFilePath)
	if err != nil {
		if !r.checkedLocalRepo && errors.Is(err, os.ErrNotExist) {
			r.checkedLocalRepo = true
			// check if the directory exists at all, and if not just stop trying to resolve local maven files
			fi, err := os.Stat(r.cfg.MavenLocalRepositoryDir)
			if errors.Is(err, os.ErrNotExist) || !fi.IsDir() {
				log.WithFields("error", err, "repositoryDir", r.cfg.MavenLocalRepositoryDir).
					Info("local maven repository is not a readable directory, stopping local resolution")
				r.cfg.UseMavenLocalRepository = false
			}
		}
		return nil, err
	}
	defer internal.CloseAndLogError(pomFile, pomFilePath)

	return decodePomXML(pomFile)
}

// findPomInRemoteRepository download the pom file from a (remote) Maven repository over HTTP
func (r *mavenResolver) findPomInRemoteRepository(ctx context.Context, groupID, artifactID, version string) (*gopom.Project, error) {
	if groupID == "" || artifactID == "" || version == "" {
		return nil, fmt.Errorf("missing/incomplete maven artifact coordinates -- groupId: '%s' artifactId: '%s', version: '%s'", groupID, artifactID, version)
	}

	requestURL, err := remotePomURL(r.cfg.MavenBaseURL, groupID, artifactID, version)
	if err != nil {
		return nil, fmt.Errorf("unable to find pom in remote due to: %w", err)
	}

	// Downloading snapshots requires additional steps to determine the latest snapshot version.
	// See: https://maven.apache.org/ref/3-LATEST/maven-repository-metadata/
	if strings.HasSuffix(version, "-SNAPSHOT") {
		return nil, fmt.Errorf("downloading snapshot artifacts is not supported, got: %s", requestURL)
	}

	cacheKey := strings.TrimPrefix(strings.TrimPrefix(requestURL, "http://"), "https://")
	reader, err := r.cacheResolveReader(cacheKey, func() (io.ReadCloser, error) {
		if err != nil {
			return nil, err
		}
		log.WithFields("url", requestURL).Info("fetching parent pom from remote maven repository")

		req, err := http.NewRequest(http.MethodGet, requestURL, nil)
		if err != nil {
			return nil, fmt.Errorf("unable to create request for Maven central: %w", err)
		}

		req = req.WithContext(ctx)

		client := http.Client{
			Timeout: r.remoteRequestTimeout,
		}

		resp, err := client.Do(req) //nolint:bodyclose
		if err != nil {
			return nil, fmt.Errorf("unable to get pom from Maven repository %v: %w", requestURL, err)
		}
		if resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("pom not found in Maven repository at: %v", requestURL)
		}
		return resp.Body, err
	})
	if err != nil {
		return nil, err
	}
	if reader, ok := reader.(io.Closer); ok {
		defer internal.CloseAndLogError(reader, requestURL)
	}
	pom, err := decodePomXML(reader)
	if err != nil {
		return nil, fmt.Errorf("unable to parse pom from Maven repository url %v: %w", requestURL, err)
	}
	return pom, nil
}

// cacheResolveReader attempts to get a reader from cache, otherwise caches the contents of the resolve() function.
// this function is guaranteed to return an unread reader for the correct contents.
// NOTE: this could be promoted to the internal cache package as a specialized version of the cache.Resolver
// if there are more users of this functionality
func (r *mavenResolver) cacheResolveReader(key string, resolve func() (io.ReadCloser, error)) (io.Reader, error) {
	reader, err := r.cache.Read(key)
	if err == nil && reader != nil {
		return reader, err
	}

	contentReader, err := resolve()
	if err != nil {
		return nil, err
	}
	defer internal.CloseAndLogError(contentReader, key)

	// store the contents to return a new reader with the same content
	contents, err := io.ReadAll(contentReader)
	if err != nil {
		return nil, err
	}
	err = r.cache.Write(key, bytes.NewBuffer(contents))
	return bytes.NewBuffer(contents), err
}

// resolveParent attempts to resolve the parent for the given pom
func (r *mavenResolver) resolveParent(ctx context.Context, pom *gopom.Project) (*gopom.Project, error) {
	if pom == nil || pom.Parent == nil {
		return nil, nil
	}
	parent := pom.Parent
	pomWithoutParent := *pom
	pomWithoutParent.Parent = nil
	groupID := r.getPropertyValue(ctx, parent.GroupID, &pomWithoutParent)
	artifactID := r.getPropertyValue(ctx, parent.ArtifactID, &pomWithoutParent)
	version := r.getPropertyValue(ctx, parent.Version, &pomWithoutParent)

	// check cache before resolving
	parentID := mavenID{groupID, artifactID, version}
	if resolvedParent, ok := r.resolved[parentID]; ok {
		return resolvedParent, nil
	}

	// check if the pom exists in the fileResolver
	parentPom := r.findParentPomByRelativePath(ctx, pom, parentID)
	if parentPom != nil {
		return parentPom, nil
	}

	// find POM normally
	return r.findPom(ctx, groupID, artifactID, version)
}

// findInheritedVersion attempts to find the version of a dependency (groupID, artifactID) by searching all parent poms and imported managed dependencies
//
//nolint:gocognit,funlen
func (r *mavenResolver) findInheritedVersion(ctx context.Context, pom *gopom.Project, groupID, artifactID string, resolutionContext ...*gopom.Project) (string, error) {
	if pom == nil {
		return "", fmt.Errorf("nil pom provided to findInheritedVersion")
	}
	if r.cfg.MaxParentRecursiveDepth > 0 && len(resolutionContext) > r.cfg.MaxParentRecursiveDepth {
		return "", fmt.Errorf("maximum depth reached attempting to resolve version for: %s:%s at: %v", groupID, artifactID, r.resolveMavenID(ctx, pom))
	}
	if slices.Contains(resolutionContext, pom) {
		return "", fmt.Errorf("cycle detected attempting to resolve version for: %s:%s at: %v", groupID, artifactID, r.resolveMavenID(ctx, pom))
	}
	resolutionContext = append(resolutionContext, pom)

	var err error
	var version string

	// check for entries in dependencyManagement first
	for _, dep := range pomManagedDependencies(pom) {
		depGroupID := r.getPropertyValue(ctx, dep.GroupID, resolutionContext...)
		depArtifactID := r.getPropertyValue(ctx, dep.ArtifactID, resolutionContext...)
		if depGroupID == groupID && depArtifactID == artifactID {
			version = r.getPropertyValue(ctx, dep.Version, resolutionContext...)
			if version != "" {
				return version, nil
			}
		}

		// imported pom files should be treated just like parent poms, they are used to define versions of dependencies
		if deref(dep.Type) == "pom" && deref(dep.Scope) == "import" {
			depVersion := r.getPropertyValue(ctx, dep.Version, resolutionContext...)

			depPom, err := r.findPom(ctx, depGroupID, depArtifactID, depVersion)
			if err != nil || depPom == nil {
				log.WithFields("error", err, "mavenID", r.resolveMavenID(ctx, pom), "dependencyID", mavenID{depGroupID, depArtifactID, depVersion}).
					Debug("unable to find imported pom looking for managed dependencies")
				continue
			}
			version, err = r.findInheritedVersion(ctx, depPom, groupID, artifactID, resolutionContext...)
			if err != nil {
				log.WithFields("error", err, "mavenID", r.resolveMavenID(ctx, pom), "dependencyID", mavenID{depGroupID, depArtifactID, depVersion}).
					Debug("error during findInheritedVersion")
			}
			if version != "" {
				return version, nil
			}
		}
	}

	// recursively check parents
	parent, err := r.resolveParent(ctx, pom)
	if err != nil {
		return "", err
	}
	if parent != nil {
		version, err = r.findInheritedVersion(ctx, parent, groupID, artifactID, resolutionContext...)
		if err != nil {
			return "", err
		}
		if version != "" {
			return version, nil
		}
	}

	// check for inherited dependencies
	for _, dep := range pomDependencies(pom) {
		depGroupID := r.getPropertyValue(ctx, dep.GroupID, resolutionContext...)
		depArtifactID := r.getPropertyValue(ctx, dep.ArtifactID, resolutionContext...)
		if depGroupID == groupID && depArtifactID == artifactID {
			version = r.getPropertyValue(ctx, dep.Version, resolutionContext...)
			if version != "" {
				return version, nil
			}
		}
	}

	return "", nil
}

// findLicenses search pom for license, traversing parent poms if needed
func (r *mavenResolver) findLicenses(ctx context.Context, groupID, artifactID, version string) ([]gopom.License, error) {
	pom, err := r.findPom(ctx, groupID, artifactID, version)
	if pom == nil || err != nil {
		return nil, err
	}
	return r.resolveLicenses(ctx, pom)
}

// resolveLicenses searches the pom for license, traversing parent poms if needed
func (r *mavenResolver) resolveLicenses(ctx context.Context, pom *gopom.Project, processing ...mavenID) ([]gopom.License, error) {
	id := r.resolveMavenID(ctx, pom)
	if slices.Contains(processing, id) {
		return nil, fmt.Errorf("cycle detected resolving licenses for: %v", id)
	}
	if r.cfg.MaxParentRecursiveDepth > 0 && len(processing) > r.cfg.MaxParentRecursiveDepth {
		return nil, fmt.Errorf("maximum parent recursive depth (%v) reached: %v", r.cfg.MaxParentRecursiveDepth, processing)
	}

	directLicenses := r.pomLicenses(ctx, pom)
	if len(directLicenses) > 0 {
		return directLicenses, nil
	}

	parent, err := r.resolveParent(ctx, pom)
	if err != nil {
		return nil, err
	}
	if parent == nil {
		return nil, nil
	}
	return r.resolveLicenses(ctx, parent, append(processing, id)...)
}

// pomLicenses appends the directly specified licenses with non-empty name or url
func (r *mavenResolver) pomLicenses(ctx context.Context, pom *gopom.Project) []gopom.License {
	var out []gopom.License
	for _, license := range deref(pom.Licenses) {
		// if we find non-empty licenses, return them
		name := r.getPropertyValue(ctx, license.Name, pom)
		url := r.getPropertyValue(ctx, license.URL, pom)
		if name != "" || url != "" {
			out = append(out, license)
		}
	}
	return out
}

func (r *mavenResolver) findParentPomByRelativePath(ctx context.Context, pom *gopom.Project, parentID mavenID) *gopom.Project {
	// don't resolve if no resolver
	if r.fileResolver == nil {
		return nil
	}

	pomLocation, hasPomLocation := r.pomLocations[pom]
	if !hasPomLocation || pom == nil || pom.Parent == nil {
		return nil
	}
	relativePath := r.getPropertyValue(ctx, pom.Parent.RelativePath, pom)
	if relativePath == "" {
		return nil
	}
	p := pomLocation.Path()
	p = path.Dir(p)
	p = path.Join(p, relativePath)
	p = path.Clean(p)
	parentLocations, err := r.fileResolver.FilesByPath(p)
	if err != nil || len(parentLocations) == 0 {
		log.WithFields("error", err, "mavenID", r.resolveMavenID(ctx, pom), "parentID", parentID, "relativePath", relativePath).
			Trace("parent pom not found by relative path")
		return nil
	}
	parentLocation := parentLocations[0]

	parentContents, err := r.fileResolver.FileContentsByLocation(parentLocation)
	if err != nil || parentContents == nil {
		log.WithFields("error", err, "mavenID", r.resolveMavenID(ctx, pom), "parentID", parentID, "parentLocation", parentLocation).
			Debug("unable to get contents of parent pom by relative path")
		return nil
	}
	defer internal.CloseAndLogError(parentContents, parentLocation.RealPath)
	parentPom, err := decodePomXML(parentContents)
	if err != nil || parentPom == nil {
		log.WithFields("error", err, "mavenID", r.resolveMavenID(ctx, pom), "parentID", parentID, "parentLocation", parentLocation).
			Debug("unable to parse parent pom")
		return nil
	}
	// ensure parent matches
	newParentID := r.resolveMavenID(ctx, parentPom)
	if newParentID.ArtifactID != parentID.ArtifactID {
		log.WithFields("newParentID", newParentID, "mavenID", r.resolveMavenID(ctx, pom), "parentID", parentID, "parentLocation", parentLocation).
			Debug("parent IDs do not match resolving parent by relative path")
		return nil
	}

	r.resolved[parentID] = parentPom
	r.pomLocations[parentPom] = parentLocation // for any future parent relativepath lookups

	return parentPom
}

// pomDependencies returns all dependencies directly defined in a project, including all defined in profiles.
// does not resolve parent dependencies
func pomDependencies(pom *gopom.Project) []gopom.Dependency {
	dependencies := deref(pom.Dependencies)
	for _, profile := range deref(pom.Profiles) {
		dependencies = append(dependencies, deref(profile.Dependencies)...)
	}
	return dependencies
}

// pomManagedDependencies returns all directly defined managed dependencies in a project pom, including all defined in profiles.
// does not resolve parent managed dependencies
func pomManagedDependencies(pom *gopom.Project) []gopom.Dependency {
	var dependencies []gopom.Dependency
	if pom.DependencyManagement != nil {
		dependencies = append(dependencies, deref(pom.DependencyManagement.Dependencies)...)
	}
	for _, profile := range deref(pom.Profiles) {
		if profile.DependencyManagement != nil {
			dependencies = append(dependencies, deref(profile.DependencyManagement.Dependencies)...)
		}
	}
	return dependencies
}
