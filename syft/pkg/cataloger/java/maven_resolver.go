package java

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vifraa/gopom"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/cache"
	"github.com/anchore/syft/internal/log"
)

// mavenID is the unique identifier for a package in Maven
type mavenID struct {
	GroupID    string
	ArtifactID string
	Version    string
}

func (m mavenID) String() string {
	return fmt.Sprintf("%s:%s:%s", m.GroupID, m.ArtifactID, m.Version)
}

func newMavenID(groupID, artifactID, version *string) mavenID {
	return mavenID{
		GroupID:    deref(groupID),
		ArtifactID: deref(artifactID),
		Version:    deref(version),
	}
}

// mavenResolver is a short-lived utility to resolve maven poms from multiple sources, including:
// the scanned filesystem, local maven cache directories, remote maven repositories, and the syft cache
type mavenResolver struct {
	cfg ArchiveCatalogerConfig
	// resolver             file.Resolver
	cache                cache.Resolver[*gopom.Project]
	resolved             map[mavenID]*gopom.Project
	remoteRequestTimeout time.Duration
	checkedLocalRepo     bool
}

func newMavenResolver(cfg ArchiveCatalogerConfig) mavenResolver {
	return mavenResolver{
		cfg:                  cfg,
		cache:                cache.GetResolver[*gopom.Project]("java/maven/pom", "v1"),
		resolved:             map[mavenID]*gopom.Project{},
		remoteRequestTimeout: time.Second * 10,
	}
}

// findPom gets a pom from cache, local repository, or downloads from a remote Maven repository depending on configuration
func (r *mavenResolver) findPom(ctx context.Context, groupID, artifactID, version string) (*gopom.Project, error) {
	if groupID == "" || artifactID == "" || version == "" {
		return nil, fmt.Errorf("invalid parent specification, require non-empty values for groupID :'%s', artifactID :'%s', version :'%s'", groupID, artifactID, version)
	}

	id := newMavenID(&groupID, &artifactID, &version)
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
		pom, err := r.findPomInRemoteRepo(ctx, groupID, artifactID, version)
		if pom != nil {
			r.resolved[id] = pom
			return pom, nil
		}
		errs = errors.Join(errs, err)
	}

	if errs != nil {
		return nil, fmt.Errorf("unable to resolve pom %s %s %s: %w", groupID, artifactID, version, errs)
	}

	return nil, nil
}

// Try to get the Pom from the users local repository in the users home dir.
// Returns (nil, false) when file cannot be found or read for any reason.
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
				log.Debugf("local maven repository is not a readable directory, stopping local resolution: %v", r.cfg.MavenLocalRepositoryDir)
				r.cfg.UseMavenLocalRepository = false
			}
		}
		return nil, err
	}
	defer internal.CloseAndLogError(pomFile, pomFilePath)

	return decodePomXML(pomFile)
}

// Download the pom file from a (remote) Maven repository over HTTP.
func (r *mavenResolver) findPomInRemoteRepo(ctx context.Context, groupID, artifactID, version string) (*gopom.Project, error) {
	if groupID == "" || artifactID == "" || version == "" {
		return nil, fmt.Errorf("missing/incomplete maven artifact coordinates -- groupId: '%s' artifactId: '%s', version: '%s'", groupID, artifactID, version)
	}

	key := fmt.Sprintf("%s:%s:%s", groupID, artifactID, version)

	// Downloading snapshots requires additional steps to determine the latest snapshot version.
	// See: https://maven.apache.org/ref/3-LATEST/maven-repository-metadata/
	if strings.HasSuffix(version, "-SNAPSHOT") {
		return nil, fmt.Errorf("downloading snapshot artifacts is not supported, got: %s", key)
	}

	return r.cache.Resolve(key, func() (*gopom.Project, error) {
		requestURL, err := r.remotePomURL(groupID, artifactID, version)
		if err != nil {
			return nil, err
		}
		log.Debugf("fetching parent pom from maven repository, at url: %s", requestURL)

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
		defer internal.CloseAndLogError(resp.Body, requestURL)
		if resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("pom not found in Maven repository at: %v", requestURL)
		}

		pom, err := decodePomXML(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("unable to parse pom from Maven repository url %v: %w", requestURL, err)
		}
		return pom, nil
	})
}

func (r *mavenResolver) remotePomURL(groupID, artifactID, version string) (requestURL string, err error) {
	return remotePomURL(r.cfg.MavenBaseURL, groupID, artifactID, version)
}

func (r *mavenResolver) findParent(ctx context.Context, pom *gopom.Project) (*gopom.Project, error) {
	if pom == nil || pom.Parent == nil {
		return nil, nil
	}
	parent := pom.Parent
	pomWithoutParent := *pom
	pomWithoutParent.Parent = nil
	groupID := r.getPropertyValue(ctx, &pomWithoutParent, parent.GroupID)
	artifactID := r.getPropertyValue(ctx, &pomWithoutParent, parent.ArtifactID)
	version := r.getPropertyValue(ctx, &pomWithoutParent, parent.Version)
	return r.findPom(ctx, groupID, artifactID, version)
}
