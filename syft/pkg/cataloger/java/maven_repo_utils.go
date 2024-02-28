package java

import (
	"context"
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

// Add all properties from the project 'pom' to the map 'allProperties' that are not already in the map.
func addMissingPropertiesToProject(allProperties map[string]string, pom *gopom.Project) {
	if pom != nil && pom.Properties != nil && pom.Properties.Entries != nil {
		for name, value := range pom.Properties.Entries {
			_, exists := allProperties[name]
			if !exists {
				allProperties[name] = value
				// log.Tracef("  Added property %s=%s to pom", name, value)
			}
		}
	} else {
		log.Tracef("addMissingPropertiesToProject: nothing to do for project: %s", *pom.ArtifactID)
	}
}

// Add all properties from the map 'additionalProperties' to the map 'allProperties' that are not already in the map.
func addMissingPropertiesToMap(allProperties, additionalProperties map[string]string) {
	if len(additionalProperties) > 0 {
		for name, value := range additionalProperties {
			_, exists := additionalProperties[name]
			if !exists {
				allProperties[name] = value
				// log.Tracef("  Added property to allProperties %s=%s", name, value)
			}
		}
	} else {
		log.Tracef("addMissingPropertiesToMap: Supplied map was empty.")
	}
}

// Add all properties from map 'properties' to the project 'pom' that are not already defined in the pom.
// This increases the chance of the 'resolveProperty' function succeeding.
func addPropertiesToProject(pom *gopom.Project, allProperties map[string]string) {

	if len(allProperties) > 0 {
		if pom.Properties == nil {
			var props gopom.Properties
			props.Entries = make(map[string]string)
			pom.Properties = &props
		}
		for name, value := range allProperties {
			_, exists := pom.Properties.Entries[name]
			if !exists {
				allProperties[name] = value
				log.Tracef("  Added property %s=%s to pom [%s, %s, %s]", name, value, *pom.GroupID, *pom.ArtifactID, *pom.Version)
			}
		}
	}
}

// Try to find the version of a dependency (groupID, artifactID) by parsing all parent poms and imported managed dependencies (maven BOMs).
// Properties are gathered in the order that they are encountered: in Maven the latest definition of a property (highest in hierarchy) is used.
// parsedPomFiles contains all previously parsed pom files encountered by earlier invocations of this function on the stack. So for the first
// call parsedPomFiles should be nill. It is used to prevent cycles (endless loops).
func recursivelyFindVersionFromManagedOrInherited(ctx context.Context, findGroupID, findArtifactID string,
	pom *gopom.Project, cfg ArchiveCatalogerConfig, parsedPomFiles map[MavenCoordinate]bool) (string, map[string]string) {

	log.Debugf("recursively finding version from managed or inherited dependencies for dependency [%v:%v] in pom [%s, %s, %s]",
		findGroupID, findArtifactID, *pom.GroupID, *pom.ArtifactID, *pom.Version)

	// Create map to keep track of parsed pom files and to prevent cycles.
	if parsedPomFiles == nil {
		parsedPomFiles = make(map[MavenCoordinate]bool)
		log.Tracef("Created parsedPomFiles")
	}
	log.Tracef("parsedPomFiles: %+v", parsedPomFiles)

	pomCoordinates := MavenCoordinate{*pom.GroupID, *pom.ArtifactID, *pom.Version}
	_, alreadyParsed := parsedPomFiles[pomCoordinates]
	if alreadyParsed {
		// Nothing new here, already parsed
		log.Info("Nothing new here, already parsed.")
		return "", nil
	} else {
		parsedPomFiles[pomCoordinates] = true
	}

	// Map with all properties defined in all parsed pom files
	var allProperties map[string]string = make(map[string]string)

	addMissingPropertiesToProject(allProperties, pom)

	// If a parent exists, first parse the parent POM. It may contain required properties and/or
	// managed dependencies.
	if pom.Parent != nil {
		parentGroupID := *pom.Parent.GroupID
		parentArtifactID := *pom.Parent.ArtifactID
		parentVersion := *pom.Parent.Version

		parentPom, err := getPomFromMavenOrCache(ctx, parentGroupID, parentArtifactID, parentVersion, cfg)

		if parentPom != nil {
			log.Infof("Found a parent pom: [%s, %s, %s]", parentGroupID, parentArtifactID, parentVersion)
			// Mark this parent pom as parsed to prevent re-parsing/cycles later on
			parsedPomFilesCache[MavenCoordinate{parentGroupID, parentArtifactID, parentVersion}] = parentPom

			addMissingPropertiesToProject(allProperties, parentPom)
			addPropertiesToProject(parentPom, allProperties)

			// TODO: Recurse into parent to gather properties/dep management?

			foundVersion := ""
			if parentPom.DependencyManagement != nil {
				foundVersion = findVersionInDependencyManagement(
					ctx, findGroupID, findArtifactID, parentPom, cfg, allProperties, parsedPomFiles)
			}
			if parentPom.Dependencies != nil {
				foundVersion = findVersionInDependencies(findGroupID, findArtifactID, parentPom)
			}

			if foundVersion != "" && !strings.HasPrefix(foundVersion, "${}") {
				foundVersion := resolveProperty(*parentPom, &foundVersion, "version")
				log.Infof("Found version [%s] for dependency: [%s, %s]", foundVersion, findGroupID, findArtifactID)
				return foundVersion, allProperties
			}
		} else {
			log.Warnf("unable to get parent pom [%s, %s, %s]: %v",
				parentGroupID, parentArtifactID, parentVersion, err)
		}
	}

	foundVersion := ""
	if pom.DependencyManagement != nil {
		foundVersion = findVersionInDependencyManagement(
			ctx, findGroupID, findArtifactID, pom, cfg, allProperties, parsedPomFiles)
	}
	if pom.Dependencies != nil {
		foundVersion = findVersionInDependencies(findGroupID, findArtifactID, pom)
	}

	log.Infof("Found version [%s] for dependency: [%s, %s]", foundVersion, findGroupID, findArtifactID)
	return foundVersion, allProperties
}

// Get a parent pom from cache or download from a Maven repository
func getPomFromMavenOrCache(ctx context.Context, parentGroupID, parentArtifactID, parentVersion string,
	cfg ArchiveCatalogerConfig) (*gopom.Project, error) {
	var err error
	parentPom, found := parsedPomFilesCache[MavenCoordinate{parentGroupID, parentArtifactID, parentVersion}]

	if !found && cfg.UseNetwork {
		parentPom, err = getPomFromMavenRepo(ctx, parentGroupID, parentArtifactID, parentVersion, cfg.MavenBaseURL)
	}
	return parentPom, err
}

// Find given dependency (groupID, artifactID) in the dependencyManagement section of project 'pom'.
// May recursively call recursivelyFindVersionFromManagedOrInherited when a Maven BOM is found.
func findVersionInDependencyManagement(ctx context.Context, findGroupID, findArtifactID string,
	pom *gopom.Project, cfg ArchiveCatalogerConfig, allProperties map[string]string, parsedPomFiles map[MavenCoordinate]bool) string {

	for _, dependency := range *pom.DependencyManagement.Dependencies {
		log.Tracef("  Found managed dependency:  [%s, %s, %s]",
			safeString(dependency.GroupID), safeString(dependency.ArtifactID), safeString(dependency.Version))

		// imported pom files should be treated just like parent poms, they are use to define versions of dependencies
		if dependency.Type != nil && dependency.Scope != nil &&
			*dependency.Type == "pom" && *dependency.Scope == "import" {

			bomVersion := resolveProperty(*pom, dependency.Version, "version")
			log.Debugf("Found BOM: [%s, %s, %s]", *dependency.GroupID, *dependency.ArtifactID, bomVersion)
			// Recurse into BOM, which should be treated just like a parent pom
			bomProject, err := getPomFromMavenOrCache(ctx, *dependency.GroupID, *dependency.ArtifactID, bomVersion, cfg)
			if err == nil {
				foundVersion, bomProperties := recursivelyFindVersionFromManagedOrInherited(ctx, findGroupID, findArtifactID, bomProject, cfg, parsedPomFiles)
				log.Debugf("Finished processing BOM: [%s, %s, %s]", *dependency.GroupID, *dependency.ArtifactID, bomVersion)
				addMissingPropertiesToMap(allProperties, bomProperties)
				addMissingPropertiesToProject(allProperties, pom)
				if foundVersion != "" {
					foundVersion = resolveProperty(*pom, dependency.Version, "version")
					if foundVersion != "" && !strings.HasPrefix(foundVersion, "${") {
						log.Tracef("Found version for managed dependency in BOM: [%s, %s, %s]", findGroupID, findArtifactID, foundVersion)
						return foundVersion
					}
				}
			}

		} else if *dependency.GroupID == findGroupID && *dependency.ArtifactID == findArtifactID {
			foundVersion := resolveProperty(*pom, dependency.Version, "version")
			if foundVersion != "" && !strings.HasPrefix(foundVersion, "${") {
				log.Tracef("Found version for managed dependency: [%s, %s, %s]", *dependency.GroupID, *dependency.ArtifactID, foundVersion)
				return foundVersion
			}
		}
	}
	log.Tracef("Dependency not found in dependencyManagement")
	return ""
}

// Find given dependency (groupID, artifactID) in the dependencies section of project 'pom'.
func findVersionInDependencies(groupID, artifactID string, pom *gopom.Project) string {

	for _, dependency := range *pom.Dependencies {
		if *dependency.GroupID == groupID && *dependency.ArtifactID == artifactID {
			depVersion := resolveProperty(*pom, dependency.Version, "version")
			// TODO: -> trace
			log.Infof("Found dependency: [%s, %s, %s]", *dependency.GroupID, *dependency.ArtifactID, depVersion)
			return depVersion
		}
	}
	log.Tracef("Dependency not found in dependencies")
	return ""
}

func recursivelyFindLicensesFromParentPom(ctx context.Context, groupID, artifactID, version string, cfg ArchiveCatalogerConfig) []string {
	log.Debugf("recursively finding license from parent Pom for artifact [%v:%v], using parent pom: [%v:%v:%v]",
		groupID, artifactID, groupID, artifactID, version)
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
	if len(groupID) == 0 || len(artifactID) == 0 || len(version) == 0 || strings.HasPrefix(version, "${") {
		return nil, fmt.Errorf("missing/incomplete maven artifact coordinates: groupId:artifactId:version = %s:%s:%s", groupID, artifactID, version)
	}
	requestURL, err := formatMavenPomURL(groupID, artifactID, version, mavenBaseURL)
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
