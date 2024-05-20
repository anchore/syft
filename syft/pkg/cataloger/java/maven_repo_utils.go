package java

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/vifraa/gopom"

	"github.com/anchore/syft/internal/log"
)

func formatMavenPomURL(groupID, artifactID, version, mavenBaseURL string) (requestURL string, err error) {
	// groupID needs to go from maven.org -> maven/org
	urlPath := strings.Split(groupID, ".")
	artifactPom := fmt.Sprintf("%s-%s.pom", artifactID, version)
	urlPath = append(urlPath, artifactID, version, artifactPom)

	// ex:"https://repo1.maven.org/maven2/groupID/artifactID/artifactPom
	requestURL, err = url.JoinPath(mavenBaseURL, urlPath...)
	if err != nil {
		return requestURL, fmt.Errorf("could not construct maven url: %w", err)
	}
	return requestURL, err
}

// An artifact can have its version defined in a parent's DependencyManagement section
func recursivelyFindVersionFromParentPom(ctx context.Context, groupID, artifactID, parentGroupID, parentArtifactID, parentVersion string, cfg ArchiveCatalogerConfig) string {
	log.Debugf("recursively finding version from parent Pom for artifact [%v:%v], using parent pom: [%v:%v:%v]",
		groupID, artifactID, parentGroupID, parentArtifactID, parentVersion)
	// As there can be nested parent poms, we'll recursively check for the version until we reach the max depth
	for i := 0; i < cfg.MaxParentRecursiveDepth; i++ {
		parentPom, err := getPomFromMavenRepo(ctx, parentGroupID, parentArtifactID, parentVersion, cfg.MavenBaseURL)
		if err != nil {
			// We don't want to abort here as the parent pom might not exist in Maven Central, we'll just log the error
			log.Tracef("unable to get parent pom from Maven central: %v", err)
			break
		}
		if parentPom != nil && parentPom.DependencyManagement != nil {
			for _, dependency := range *parentPom.DependencyManagement.Dependencies {
				if groupID == *dependency.GroupID && artifactID == *dependency.ArtifactID && dependency.Version != nil {
					return *dependency.Version
				}
			}
		}
		if parentPom == nil || parentPom.Parent == nil {
			break
		}
		parentGroupID = *parentPom.Parent.GroupID
		parentArtifactID = *parentPom.Parent.ArtifactID
		parentVersion = *parentPom.Parent.Version
	}
	return ""
}

func recursivelyFindLicensesFromParentPom(ctx context.Context, groupID, artifactID, version string, cfg ArchiveCatalogerConfig) []string {
	var licenses []string
	// As there can be nested parent poms, we'll recursively check for licenses until we reach the max depth
	for i := 0; i < cfg.MaxParentRecursiveDepth; i++ {
		parentPom, err := getPomFromMavenRepo(ctx, groupID, artifactID, version, cfg.MavenBaseURL)
		if err != nil {
			// We don't want to abort here as the parent pom might not exist in Maven Central, we'll just log the error
			log.Tracef("unable to get parent pom from Maven central: %v", err)
			return []string{}
		}
		parentLicenses := parseLicensesFromPom(parentPom)
		if len(parentLicenses) > 0 || parentPom == nil || parentPom.Parent == nil {
			licenses = parentLicenses
			break
		}

		groupID = *parentPom.Parent.GroupID
		artifactID = *parentPom.Parent.ArtifactID
		version = *parentPom.Parent.Version
	}

	return licenses
}

func getPomFromMavenRepo(ctx context.Context, groupID, artifactID, version, mavenBaseURL string) (*gopom.Project, error) {
	if len(groupID) == 0 || len(artifactID) == 0 || len(version) == 0 {
		return nil, errors.New("missing/incomplete maven artiface coordinates, cannot download pom from repository")
	}
	requestURL, err := formatMavenPomURL(groupID, artifactID, version, mavenBaseURL)
	log.Tracef("Requesting pom for artifact %s:%s:%s", groupID, artifactID, version)
	if err != nil {
		return nil, err
	}
	log.Tracef("trying to fetch parent pom from Maven central %s", requestURL)

	mavenRequest, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to format request for Maven central: %w", err)
	}

	httpClient := &http.Client{
		Timeout: time.Second * 10,
	}

	mavenRequest = mavenRequest.WithContext(ctx)

	resp, err := httpClient.Do(mavenRequest)
	if err != nil {
		return nil, fmt.Errorf("unable to get pom from Maven central: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Errorf("unable to close body: %+v", err)
		}
	}()

	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to parse pom from Maven central: %w", err)
	}

	pom, err := decodePomXML(strings.NewReader(string(bytes)))
	if err != nil {
		return nil, fmt.Errorf("unable to parse pom from Maven central: %w", err)
	}

	return &pom, nil
}

func parseLicensesFromPom(pom *gopom.Project) []string {
	var licenses []string
	if pom != nil && pom.Licenses != nil {
		for _, license := range *pom.Licenses {
			if license.Name != nil {
				licenses = append(licenses, *license.Name)
			} else if license.URL != nil {
				licenses = append(licenses, *license.URL)
			}
		}
	}

	return licenses
}
