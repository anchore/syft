package maven

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

// ID is the unique identifier for a package in Maven
type ID struct {
	GroupID    string
	ArtifactID string
	Version    string
}

func NewID(groupID, artifactID, version string) ID {
	return ID{
		GroupID:    groupID,
		ArtifactID: artifactID,
		Version:    version,
	}
}

func (m ID) String() string {
	return fmt.Sprintf("(groupId: %s artifactId: %s version: %s)", m.GroupID, m.ArtifactID, m.Version)
}

// Valid indicates that the given maven ID has values for groupId, artifactId, and version
func (m ID) Valid() bool {
	return m.GroupID != "" && m.ArtifactID != "" && m.Version != ""
}

var expressionMatcher = regexp.MustCompile("[$][{][^}]+[}]")

// Resolver is a short-lived utility to resolve maven poms from multiple sources, including:
// the scanned filesystem, local maven cache directories, remote maven repositories, and the syft cache
type Resolver struct {
	cfg                  Config
	cache                cache.Cache
	resolved             map[ID]*Project
	remoteRequestTimeout time.Duration
	checkedLocalRepo     bool
	// fileResolver and pomLocations are used to resolve parent poms by relativePath
	fileResolver file.Resolver
	pomLocations map[*Project]file.Location
}

// NewResolver constructs a new Resolver with the given configuration.
// NOTE: the fileResolver is optional and if provided will be used to resolve parent poms by relative path
func NewResolver(fileResolver file.Resolver, cfg Config) *Resolver {
	return &Resolver{
		cfg:                  cfg,
		cache:                cache.GetManager().GetCache("java/maven/repo", "v1"),
		resolved:             map[ID]*Project{},
		remoteRequestTimeout: time.Second * 10,
		fileResolver:         fileResolver,
		pomLocations:         map[*Project]file.Location{},
	}
}

// ResolveProperty gets property values by emulating maven property resolution logic, looking in the project's variables
// as well as supporting the project expressions like ${project.parent.groupId}.
// Properties which are not resolved result in empty string ""
func (r *Resolver) ResolveProperty(ctx context.Context, pom *Project, propertyValue *string) string {
	return r.resolvePropertyValue(ctx, propertyValue, nil, pom)
}

// resolvePropertyValue resolves property values by emulating maven property resolution logic, looking in the project's variables
// as well as supporting the project expressions like ${project.parent.groupId}.
// Properties which are not resolved result in empty string ""
func (r *Resolver) resolvePropertyValue(ctx context.Context, propertyValue *string, resolvingProperties []string, resolutionContext ...*Project) string {
	if propertyValue == nil {
		return ""
	}
	resolved, err := r.resolveExpression(ctx, resolutionContext, *propertyValue, resolvingProperties)
	if err != nil {
		log.WithFields("error", err, "propertyValue", *propertyValue).Trace("error resolving maven property")
		return ""
	}
	return resolved
}

// resolveExpression resolves an expression, which may be a plain string or a string with ${ property.references }
func (r *Resolver) resolveExpression(ctx context.Context, resolutionContext []*Project, expression string, resolvingProperties []string) (string, error) {
	log.Tracef("resolving expression: '%v' in context: %v", expression, resolutionContext)

	var errs error
	return expressionMatcher.ReplaceAllStringFunc(expression, func(match string) string {
		log.Tracef("resolving property: '%v' in context: %v", expression, resolutionContext)
		propertyExpression := strings.TrimSpace(match[2 : len(match)-1]) // remove leading ${ and trailing }
		resolved, err := r.resolveProperty(ctx, resolutionContext, propertyExpression, resolvingProperties)
		if err != nil {
			errs = errors.Join(errs, err)
			return ""
		}
		return resolved
	}), errs
}

// resolveProperty resolves properties recursively from the root project
func (r *Resolver) resolveProperty(ctx context.Context, resolutionContext []*Project, propertyExpression string, resolvingProperties []string) (string, error) {
	// prevent cycles
	if slices.Contains(resolvingProperties, propertyExpression) {
		return "", fmt.Errorf("cycle detected resolving: %s", propertyExpression)
	}
	if len(resolutionContext) == 0 {
		return "", fmt.Errorf("no project variable resolution context provided for expression: '%s'", propertyExpression)
	}
	resolvingProperties = append(resolvingProperties, propertyExpression)

	// only resolve project. properties in the context of the current project pom
	value, err := r.resolveProjectProperty(ctx, resolutionContext, resolutionContext[len(resolutionContext)-1], propertyExpression, resolvingProperties)
	if err != nil {
		return value, err
	}
	if value != "" {
		return value, nil
	}

	var resolvingParents []*Project
	for _, pom := range resolutionContext {
		current := pom
		for parentDepth := 0; current != nil; parentDepth++ {
			if slices.Contains(resolvingParents, current) {
				log.WithFields("property", propertyExpression, "mavenID", r.resolveID(ctx, resolvingProperties, resolvingParents...)).Error("got circular reference while resolving property")
				break // some sort of circular reference -- we've already seen this project
			}
			if r.cfg.MaxParentRecursiveDepth > 0 && parentDepth > r.cfg.MaxParentRecursiveDepth {
				return "", fmt.Errorf("maximum parent recursive depth (%v) reached resolving property: %v", r.cfg.MaxParentRecursiveDepth, propertyExpression)
			}
			if current.Properties != nil && current.Properties.Entries != nil {
				if value, ok := current.Properties.Entries[propertyExpression]; ok {
					return r.resolveExpression(ctx, resolutionContext, value, resolvingProperties) // property values can contain expressions
				}
			}
			resolvingParents = append(resolvingParents, current)
			current, err = r.resolveParent(ctx, current, resolvingProperties...)
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
func (r *Resolver) resolveProjectProperty(ctx context.Context, resolutionContext []*Project, pom *Project, propertyExpression string, resolving []string) (string, error) {
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

// ResolveParent resolves the parent definition, and returns a POM for the parent, which is possibly incomplete, or nil
func (r *Resolver) ResolveParent(ctx context.Context, pom *Project) (*Project, error) {
	if pom == nil || pom.Parent == nil {
		return nil, nil
	}

	parent, err := r.resolveParent(ctx, pom)
	if parent != nil {
		return parent, err
	}

	groupID := r.ResolveProperty(ctx, pom, pom.Parent.GroupID)
	if groupID == "" {
		groupID = r.ResolveProperty(ctx, pom, pom.GroupID)
	}
	artifactID := r.ResolveProperty(ctx, pom, pom.Parent.ArtifactID)
	version := r.ResolveProperty(ctx, pom, pom.Parent.Version)

	if artifactID != "" && version != "" {
		return &Project{
			GroupID:    &groupID,
			ArtifactID: &artifactID,
			Version:    &version,
		}, nil
	}

	return nil, fmt.Errorf("unsufficient information to create a parent pom project, id: %s", NewID(groupID, artifactID, version))
}

// ResolveID creates an ID from a pom, resolving parent information as necessary
func (r *Resolver) ResolveID(ctx context.Context, pom *Project) ID {
	return r.resolveID(ctx, nil, pom)
}

// resolveID creates a new ID from a pom, resolving parent information as necessary
func (r *Resolver) resolveID(ctx context.Context, resolvingProperties []string, resolutionContext ...*Project) ID {
	if len(resolutionContext) == 0 || resolutionContext[0] == nil {
		return ID{}
	}
	pom := resolutionContext[len(resolutionContext)-1] // get topmost pom
	if pom == nil {
		return ID{}
	}

	groupID := r.resolvePropertyValue(ctx, pom.GroupID, resolvingProperties, resolutionContext...)
	artifactID := r.resolvePropertyValue(ctx, pom.ArtifactID, resolvingProperties, resolutionContext...)
	version := r.resolvePropertyValue(ctx, pom.Version, resolvingProperties, resolutionContext...)
	if pom.Parent != nil {
		// groupId and version are able to be inherited from the parent, but importantly: not artifactId. see:
		// https://maven.apache.org/guides/introduction/introduction-to-the-pom.html#the-solution
		if groupID == "" && deref(pom.GroupID) == "" {
			groupID = r.resolvePropertyValue(ctx, pom.Parent.GroupID, resolvingProperties, resolutionContext...)
		}
		if version == "" && deref(pom.Version) == "" {
			version = r.resolvePropertyValue(ctx, pom.Parent.Version, resolvingProperties, resolutionContext...)
		}
	}
	return ID{groupID, artifactID, version}
}

// ResolveDependencyID creates an ID from a dependency element in a pom, resolving information as necessary
func (r *Resolver) ResolveDependencyID(ctx context.Context, pom *Project, dep Dependency) ID {
	if pom == nil {
		return ID{}
	}

	groupID := r.resolvePropertyValue(ctx, dep.GroupID, nil, pom)
	artifactID := r.resolvePropertyValue(ctx, dep.ArtifactID, nil, pom)
	version := r.resolvePropertyValue(ctx, dep.Version, nil, pom)

	var err error
	if version == "" {
		version, err = r.resolveInheritedVersion(ctx, pom, groupID, artifactID)
	}

	depID := ID{groupID, artifactID, version}

	if err != nil {
		log.WithFields("error", err, "ID", r.ResolveID(ctx, pom), "dependencyID", depID)
	}

	return depID
}

// FindPom gets a pom from cache, local repository, or from a remote Maven repository depending on configuration
func (r *Resolver) FindPom(ctx context.Context, groupID, artifactID, version string) (*Project, error) {
	if groupID == "" || artifactID == "" || version == "" {
		return nil, fmt.Errorf("invalid maven pom specification, require non-empty values for groupID: '%s', artifactID: '%s', version: '%s'", groupID, artifactID, version)
	}

	id := ID{groupID, artifactID, version}
	existingPom := r.resolved[id]

	if existingPom != nil {
		return existingPom, nil
	}

	var errs error

	// try to resolve first from local maven repo
	if r.cfg.UseLocalRepository {
		pom, err := r.findPomInLocalRepository(groupID, artifactID, version)
		if pom != nil {
			r.resolved[id] = pom
			return pom, nil
		}
		errs = errors.Join(errs, err)
	}

	// resolve via network maven repository
	if r.cfg.UseNetwork {
		pom, err := r.findPomInRemotes(ctx, groupID, artifactID, version)
		if pom != nil {
			r.resolved[id] = pom
			return pom, nil
		}
		errs = errors.Join(errs, err)
	}

	return nil, fmt.Errorf("unable to resolve pom %s %s %s: %w", groupID, artifactID, version, errs)
}

// findPomInLocalRepository attempts to get the POM from the users local maven repository
func (r *Resolver) findPomInLocalRepository(groupID, artifactID, version string) (*Project, error) {
	groupPath := filepath.Join(strings.Split(groupID, ".")...)
	pomFilePath := filepath.Join(r.cfg.LocalRepositoryDir, groupPath, artifactID, version, artifactID+"-"+version+".pom")
	pomFile, err := os.Open(pomFilePath)
	if err != nil {
		if !r.checkedLocalRepo && errors.Is(err, os.ErrNotExist) {
			r.checkedLocalRepo = true
			// check if the directory exists at all, and if not just stop trying to resolve local maven files
			fi, err := os.Stat(r.cfg.LocalRepositoryDir)
			if errors.Is(err, os.ErrNotExist) || !fi.IsDir() {
				log.WithFields("error", err, "repositoryDir", r.cfg.LocalRepositoryDir).
					Info("local maven repository is not a readable directory, stopping local resolution")
				r.cfg.UseLocalRepository = false
			}
		}
		return nil, err
	}
	defer internal.CloseAndLogError(pomFile, pomFilePath)

	return ParsePomXML(pomFile)
}

// findPomInRemotes download the pom file from all configured Maven repositories over HTTP
func (r *Resolver) findPomInRemotes(ctx context.Context, groupID, artifactID, version string) (*Project, error) {
	var errs error
	for _, repo := range r.cfg.Repositories {
		pom, err := r.findPomInRemoteRepository(ctx, repo, groupID, artifactID, version)
		if err != nil {
			errs = errors.Join(errs, err)
		}
		if pom != nil {
			return pom, err
		}
	}
	return nil, fmt.Errorf("pom for %v not found in any remote repository: %w", ID{groupID, artifactID, version}, errs)
}

// findPomInRemoteRepository download the pom file from a (remote) Maven repository over HTTP
func (r *Resolver) findPomInRemoteRepository(ctx context.Context, repo string, groupID, artifactID, version string) (*Project, error) {
	if groupID == "" || artifactID == "" || version == "" {
		return nil, fmt.Errorf("missing/incomplete maven artifact coordinates -- groupId: '%s' artifactId: '%s', version: '%s'", groupID, artifactID, version)
	}

	requestURL, err := remotePomURL(repo, groupID, artifactID, version)
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

		resp, err := client.Do(req)
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
	pom, err := ParsePomXML(reader)
	if err != nil {
		return nil, fmt.Errorf("unable to parse pom from Maven repository url %v: %w", requestURL, err)
	}
	return pom, nil
}

// cacheResolveReader attempts to get a reader from cache, otherwise caches the contents of the resolve() function.
// this function is guaranteed to return an unread reader for the correct contents.
// NOTE: this could be promoted to the internal cache package as a specialized version of the cache.Resolver
// if there are more users of this functionality
func (r *Resolver) cacheResolveReader(key string, resolve func() (io.ReadCloser, error)) (io.Reader, error) {
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
func (r *Resolver) resolveParent(ctx context.Context, pom *Project, resolvingProperties ...string) (*Project, error) {
	if pom == nil || pom.Parent == nil {
		return nil, nil
	}
	parent := pom.Parent
	pomWithoutParent := *pom
	pomWithoutParent.Parent = nil
	groupID := r.resolvePropertyValue(ctx, parent.GroupID, resolvingProperties, &pomWithoutParent)
	artifactID := r.resolvePropertyValue(ctx, parent.ArtifactID, resolvingProperties, &pomWithoutParent)
	version := r.resolvePropertyValue(ctx, parent.Version, resolvingProperties, &pomWithoutParent)

	// check cache before resolving
	parentID := ID{groupID, artifactID, version}
	if resolvedParent, ok := r.resolved[parentID]; ok {
		return resolvedParent, nil
	}

	// check if the pom exists in the fileResolver
	parentPom := r.findParentPomByRelativePath(ctx, pom, parentID, resolvingProperties)
	if parentPom != nil {
		return parentPom, nil
	}

	// find POM normally
	return r.FindPom(ctx, groupID, artifactID, version)
}

// resolveInheritedVersion attempts to find the version of a dependency (groupID, artifactID) by searching all parent poms and imported managed dependencies
//
//nolint:gocognit
func (r *Resolver) resolveInheritedVersion(ctx context.Context, pom *Project, groupID, artifactID string, resolutionContext ...*Project) (string, error) {
	if pom == nil {
		return "", fmt.Errorf("nil pom provided to findInheritedVersion")
	}
	if r.cfg.MaxParentRecursiveDepth > 0 && len(resolutionContext) > r.cfg.MaxParentRecursiveDepth {
		return "", fmt.Errorf("maximum depth reached attempting to resolve version for: %s:%s at: %v", groupID, artifactID, r.ResolveID(ctx, pom))
	}
	if slices.Contains(resolutionContext, pom) {
		return "", fmt.Errorf("cycle detected attempting to resolve version for: %s:%s at: %v", groupID, artifactID, r.ResolveID(ctx, pom))
	}
	resolutionContext = append(resolutionContext, pom)

	var err error
	var version string

	// check for entries in dependencyManagement first
	for _, dep := range pomManagedDependencies(pom) {
		depGroupID := r.resolvePropertyValue(ctx, dep.GroupID, nil, resolutionContext...)
		depArtifactID := r.resolvePropertyValue(ctx, dep.ArtifactID, nil, resolutionContext...)
		if depGroupID == groupID && depArtifactID == artifactID {
			version = r.resolvePropertyValue(ctx, dep.Version, nil, resolutionContext...)
			if version != "" {
				return version, nil
			}
		}

		// imported pom files should be treated just like parent poms, they are used to define versions of dependencies
		if deref(dep.Type) == "pom" && deref(dep.Scope) == "import" {
			depVersion := r.resolvePropertyValue(ctx, dep.Version, nil, resolutionContext...)

			depPom, err := r.FindPom(ctx, depGroupID, depArtifactID, depVersion)
			if err != nil || depPom == nil {
				log.WithFields("error", err, "ID", r.ResolveID(ctx, pom), "dependencyID", ID{depGroupID, depArtifactID, depVersion}).
					Debug("unable to find imported pom looking for managed dependencies")
				continue
			}
			version, err = r.resolveInheritedVersion(ctx, depPom, groupID, artifactID, resolutionContext...)
			if err != nil {
				log.WithFields("error", err, "ID", r.ResolveID(ctx, pom), "dependencyID", ID{depGroupID, depArtifactID, depVersion}).
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
		version, err = r.resolveInheritedVersion(ctx, parent, groupID, artifactID, resolutionContext...)
		if err != nil {
			return "", err
		}
		if version != "" {
			return version, nil
		}
	}

	// check for inherited dependencies
	for _, dep := range DirectPomDependencies(pom) {
		depGroupID := r.resolvePropertyValue(ctx, dep.GroupID, nil, resolutionContext...)
		depArtifactID := r.resolvePropertyValue(ctx, dep.ArtifactID, nil, resolutionContext...)
		if depGroupID == groupID && depArtifactID == artifactID {
			version = r.resolvePropertyValue(ctx, dep.Version, nil, resolutionContext...)
			if version != "" {
				return version, nil
			}
		}
	}

	return "", nil
}

// FindLicenses attempts to find a pom, and once found attempts to resolve licenses traversing
// parent poms as necessary
func (r *Resolver) FindLicenses(ctx context.Context, groupID, artifactID, version string) ([]gopom.License, error) {
	pom, err := r.FindPom(ctx, groupID, artifactID, version)
	if pom == nil || err != nil {
		return nil, err
	}
	return r.resolveLicenses(ctx, pom)
}

// ResolveLicenses searches the pom for license, resolving and traversing parent poms if needed
func (r *Resolver) ResolveLicenses(ctx context.Context, pom *Project) ([]License, error) {
	return r.resolveLicenses(ctx, pom)
}

// resolveLicenses searches the pom for license, traversing parent poms if needed
func (r *Resolver) resolveLicenses(ctx context.Context, pom *Project, processing ...ID) ([]License, error) {
	id := r.ResolveID(ctx, pom)
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
func (r *Resolver) pomLicenses(ctx context.Context, pom *Project) []License {
	var out []License
	for _, license := range deref(pom.Licenses) {
		// if we find non-empty licenses, return them
		name := r.resolvePropertyValue(ctx, license.Name, nil, pom)
		url := r.resolvePropertyValue(ctx, license.URL, nil, pom)
		if name != "" || url != "" {
			out = append(out, license)
		}
	}
	return out
}

func (r *Resolver) findParentPomByRelativePath(ctx context.Context, pom *Project, parentID ID, resolvingProperties []string) *Project {
	// can't resolve without a file resolver
	if r.fileResolver == nil {
		return nil
	}

	pomLocation, hasPomLocation := r.pomLocations[pom]
	if !hasPomLocation || pom == nil || pom.Parent == nil {
		return nil
	}
	relativePath := r.resolvePropertyValue(ctx, pom.Parent.RelativePath, resolvingProperties, pom)
	if relativePath == "" {
		return nil
	}
	p := pomLocation.Path()
	p = path.Dir(p)
	p = path.Join(p, relativePath)
	p = path.Clean(p)
	if !strings.HasSuffix(p, ".xml") {
		p = path.Join(p, "pom.xml")
	}
	parentLocations, err := r.fileResolver.FilesByPath(p)
	if err != nil || len(parentLocations) == 0 {
		log.WithFields("error", err, "mavenID", r.resolveID(ctx, resolvingProperties, pom), "parentID", parentID, "relativePath", relativePath).
			Trace("parent pom not found by relative path")
		return nil
	}
	parentLocation := parentLocations[0]

	parentContents, err := r.fileResolver.FileContentsByLocation(parentLocation)
	if err != nil || parentContents == nil {
		log.WithFields("error", err, "mavenID", r.resolveID(ctx, resolvingProperties, pom), "parentID", parentID, "parentLocation", parentLocation).
			Debug("unable to get contents of parent pom by relative path")
		return nil
	}
	defer internal.CloseAndLogError(parentContents, parentLocation.RealPath)
	parentPom, err := ParsePomXML(parentContents)
	if err != nil || parentPom == nil {
		log.WithFields("error", err, "mavenID", r.resolveID(ctx, resolvingProperties, pom), "parentID", parentID, "parentLocation", parentLocation).
			Debug("unable to parse parent pom")
		return nil
	}
	// ensure parent matches
	newParentID := r.resolveID(ctx, resolvingProperties, parentPom)
	if newParentID.ArtifactID != parentID.ArtifactID {
		log.WithFields("newParentID", newParentID, "mavenID", r.resolveID(ctx, resolvingProperties, pom), "parentID", parentID, "parentLocation", parentLocation).
			Debug("parent IDs do not match resolving parent by relative path")
		return nil
	}

	r.resolved[parentID] = parentPom
	r.pomLocations[parentPom] = parentLocation // for any future parent relativePath lookups

	return parentPom
}

// AddPom allows for adding known pom files with locations within the file resolver, these locations may be used
// while resolving parent poms by relative path
func (r *Resolver) AddPom(ctx context.Context, pom *Project, location file.Location) {
	r.pomLocations[pom] = location
	// by calling resolve ID here, this will lookup necessary parent poms by relative path, and
	// track any poms we found with complete version information if enough is available to resolve
	id := r.ResolveID(ctx, pom)
	if id.Valid() {
		_, existing := r.resolved[id]
		if !existing {
			r.resolved[id] = pom
		}
	}
}

// DirectPomDependencies returns all dependencies directly defined in a project, including all defined in profiles.
// This does not resolve any parent or transitive dependencies
func DirectPomDependencies(pom *Project) []Dependency {
	dependencies := deref(pom.Dependencies)
	for _, profile := range deref(pom.Profiles) {
		dependencies = append(dependencies, deref(profile.Dependencies)...)
	}
	return dependencies
}

// pomManagedDependencies returns all directly defined managed dependencies in a project pom, including all defined in profiles.
// does not resolve parent managed dependencies
func pomManagedDependencies(pom *Project) []Dependency {
	var dependencies []Dependency
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

// deref dereferences ptr if not nil, or returns the type default value if ptr is nil
func deref[T any](ptr *T) T {
	if ptr == nil {
		var t T
		return t
	}
	return *ptr
}
