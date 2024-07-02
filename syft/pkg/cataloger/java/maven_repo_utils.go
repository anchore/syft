package java

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vifraa/gopom"

	"github.com/anchore/syft/internal/log"
)

// mavenCoordinate is the unique identifier for a package in Maven.
type mavenCoordinate struct {
	GroupID    string
	ArtifactID string
	Version    string
}

// Map containing all pom.xml files that have been parsed. They are cached because properties might have been added
// and also to prevent downloading multiple times from a remote repository.
var parsedPomFilesCache map[mavenCoordinate]*gopom.Project = make(map[mavenCoordinate]*gopom.Project)

var checkedForMavenLocalRepo = false
var mavenLocalRepoDir = ""

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

// Try to find the version of a dependency (groupID, artifactID) by parsing all parent poms and imported managed dependencies (maven BOMs).
// Properties are gathered in the order that they are encountered: in Maven the latest definition of a property (highest in hierarchy) is used.
// processedPomFiles contains all previously processed pom files encountered by earlier invocations of this function on the stack. So for the first
// call processedPomFiles should be nil. It is used to prevent cycles (endless loops).
func recursivelyFindVersionFromManagedOrInherited(ctx context.Context, findGroupID, findArtifactID string,
	pom *gopom.Project, cfg ArchiveCatalogerConfig, allProperties map[string]string, processedPomFiles map[mavenCoordinate]bool) string {
	// Create map to keep track of processed pom files and to prevent cycles.
	if processedPomFiles == nil {
		processedPomFiles = make(map[mavenCoordinate]bool)
	}
	log.Debugf("recursively finding version from managed or inherited dependencies for dependency [%v:%v] in pom [%s, %s, %s]. recursion depth: %d",
		findGroupID, findArtifactID, *pom.GroupID, *pom.ArtifactID, *pom.Version, len(processedPomFiles))

	pomCoordinates := mavenCoordinate{*pom.GroupID, *pom.ArtifactID, *pom.Version}
	_, alreadyProcessed := processedPomFiles[pomCoordinates]
	if alreadyProcessed {
		log.Debug("skipping already processed pom.")
		return ""
	}

	processedPomFiles[pomCoordinates] = true

	addMissingPropertiesFromProject(allProperties, pom)

	foundDepMngVersion := ""
	if pom.DependencyManagement != nil {
		foundDepMngVersion = findVersionInDependencyManagement(
			ctx, findGroupID, findArtifactID, pom, cfg, allProperties, processedPomFiles)
	}
	if isPropertyResolved(foundDepMngVersion) {
		return foundDepMngVersion
	}

	// If a parent exists, search it recursively.
	foundRecVersion := ""
	if pom.Parent != nil {
		parentGroupID := *pom.Parent.GroupID
		parentArtifactID := *pom.Parent.ArtifactID
		parentVersion := *pom.Parent.Version

		parentPom, err := getPomFromCacheOrMaven(ctx, parentGroupID, parentArtifactID, parentVersion, allProperties, cfg)

		if parentPom != nil {
			log.Debugf("found a parent pom: [%s, %s, %s]", *parentPom.GroupID, *parentPom.ArtifactID, *parentPom.Version)
			foundRecVersion = recursivelyFindVersionFromManagedOrInherited(
				ctx, findGroupID, findArtifactID, parentPom, cfg, allProperties, processedPomFiles)
			addMissingPropertiesFromProject(allProperties, pom)
			addPropertiesToProject(pom, allProperties)
		} else {
			log.Warnf("unable to get parent pom [%s, %s, %s]: %v",
				parentGroupID, parentArtifactID, parentVersion, err)
		}
	}

	foundVersion := resolveProperty(*pom, &foundRecVersion, getPropertyName(foundRecVersion))

	// foundDepMngVersion may contain the version in a property that could not previously be resolved.
	if !isPropertyResolved(foundVersion) && foundDepMngVersion != "" {
		foundDepMngVersion = resolveProperty(*pom, &foundDepMngVersion, getPropertyName(foundDepMngVersion))

		if isPropertyResolved(foundDepMngVersion) {
			foundVersion = foundDepMngVersion
		}
	}

	if foundVersion == "" {
		log.Tracef("no version found for dependency: [%s, %s]", findGroupID, findArtifactID)
	} else {
		log.Debugf("found version [%s] for dependency: [%s, %s]", foundVersion, findGroupID, findArtifactID)
	}
	return foundVersion
}

// Returns true when value is not empty and does not start with "${" (contains an unresolved property).
func isPropertyResolved(value string) bool {
	return value != "" && !strings.HasPrefix(value, "${")
}

// Find given dependency (groupID, artifactID) in the dependencyManagement section of project 'pom'.
// May recursively call recursivelyFindVersionFromManagedOrInherited when a Maven BOM is found.
func findVersionInDependencyManagement(ctx context.Context, findGroupID, findArtifactID string,
	pom *gopom.Project, cfg ArchiveCatalogerConfig, allProperties map[string]string, processedPomFiles map[mavenCoordinate]bool) string {
	for _, dependency := range *getPomManagedDependencies(pom) {
		log.Tracef("got managed dependency:  [%s, %s, %s]",
			safeString(dependency.GroupID), safeString(dependency.ArtifactID), safeString(dependency.Version))

		// imported pom files should be treated just like parent poms, they are use to define versions of dependencies
		if safeString(dependency.Type) == "pom" && safeString(dependency.Scope) == "import" {
			bomVersion := resolveProperty(*pom, dependency.Version, getPropertyName(*dependency.Version))
			log.Debugf("found BOM: [%s, %s, %s]", *dependency.GroupID, *dependency.ArtifactID, bomVersion)

			// Recurse into BOM, which should be treated just like a parent pom
			bomProject, err := getPomFromCacheOrMaven(ctx, *dependency.GroupID, *dependency.ArtifactID, bomVersion, allProperties, cfg)

			if err == nil && bomProject != nil {
				foundVersion := recursivelyFindVersionFromManagedOrInherited(
					ctx, findGroupID, findArtifactID, bomProject, cfg, allProperties, processedPomFiles)

				log.Tracef("finished processing BOM: [%s, %s, %s], found version: [%s]", *dependency.GroupID, *dependency.ArtifactID, bomVersion, foundVersion)

				addMissingPropertiesFromProject(allProperties, pom)

				if isPropertyResolved(foundVersion) {
					return foundVersion
				}
				if foundVersion != "" {
					foundVersion = resolveProperty(*pom, dependency.Version, getPropertyName(*dependency.Version))
					if isPropertyResolved(foundVersion) {
						log.Debugf("found version for managed dependency in BOM: [%s, %s, %s]", findGroupID, findArtifactID, foundVersion)
						return foundVersion
					}
				}
			}
		} else if *dependency.GroupID == findGroupID && *dependency.ArtifactID == findArtifactID {
			foundVersion := resolveProperty(*pom, dependency.Version, getPropertyName(*dependency.Version))
			if isPropertyResolved(foundVersion) {
				log.Debugf("found version for managed dependency: [%s, %s, %s]", *dependency.GroupID, *dependency.ArtifactID, foundVersion)
				return foundVersion
			}
			if strings.HasPrefix(foundVersion, "${") {
				log.Tracef("found version in property reference for managed dependency: [%s, %s, %s]", *dependency.GroupID, *dependency.ArtifactID, foundVersion)
				return foundVersion
			}
		}
	}
	log.Tracef("dependency not found in dependencyManagement")
	return ""
}

// Search pom for license, traversing parent poms if needed. Also returns if a pom file was found in order to differentiate between no pom and no license found.
func recursivelyFindLicensesFromParentPom(ctx context.Context, groupID, artifactID, version string, cfg ArchiveCatalogerConfig) ([]string, bool) {
	log.Debugf("recursively finding licenses from parent Pom for artifact [%v:%v], using parent pom: [%v:%v:%v]",
		groupID, artifactID, groupID, artifactID, version)
	var licenses []string
	var foundPom = false
	processedPomFiles := make(map[mavenCoordinate]bool)

	// As there can be nested parent poms, we'll recursively check for licenses until no parent is found
	recursionLevel := 0
	for safeString(&artifactID) != "" {
		log.Tracef("recursively find licenses for [%s, %s, %s], recursion level: %d", groupID, artifactID, version, recursionLevel)
		recursionLevel++

		parentPom, err := getPomFromCacheOrMaven(ctx, groupID, artifactID, version, make(map[string]string), cfg)
		if err != nil {
			// We don't want to abort here as the parent pom might not exist in Maven Central, we'll just log the error
			log.Tracef("unable to get parent pom: %v", err)
			return []string{}, foundPom
		}
		parentLicenses := parseLicensesFromPom(parentPom)
		if len(parentLicenses) > 0 || parentPom == nil || parentPom.Parent == nil {
			licenses = parentLicenses
			foundPom = true
			break
		}
		// Check for cycle and store processed pom ID when not
		pomCoordinates := mavenCoordinate{*parentPom.Parent.GroupID, *parentPom.Parent.ArtifactID, *parentPom.Parent.Version}
		_, alreadyProcessed := processedPomFiles[pomCoordinates]
		if alreadyProcessed {
			log.Debug("already processed parent pom, stop searching.")
			break
		}

		processedPomFiles[pomCoordinates] = true

		groupID = pomCoordinates.GroupID
		artifactID = pomCoordinates.ArtifactID
		version = pomCoordinates.Version
	}

	return licenses, foundPom
}

// Get a parent pom from cache, local repository or download from a Maven repository
func getPomFromCacheOrMaven(ctx context.Context, groupID, artifactID, version string, allProperties map[string]string,
	cfg ArchiveCatalogerConfig) (*gopom.Project, error) {
	var err error

	if !isPropertyResolved(version) {
		return nil, fmt.Errorf("cannot get POM without resolved version: %s", version)
	}

	// Try get from cache first.
	parentPom, found := parsedPomFilesCache[mavenCoordinate{groupID, artifactID, version}]

	if found {
		return parentPom, err
	}

	// Next try to get from local file system (Maven local repository).
	if cfg.UseMavenLocalRepository {
		parentPom, found = getPomFromMavenUserLocalRepository(groupID, artifactID, version, cfg)
	}

	if !found && cfg.UseNetwork {
		// If all fails, then try to get from Maven repository over HTTP
		parentPom, err = getPomFromMavenRepo(ctx, groupID, artifactID, version, cfg.MavenBaseURL)
		if err != nil && parentPom != nil {
			found = true
		}
	}

	if found {
		// Get and add all properties defined in parent poms to this project for resolving properties later on.
		if parentPom.Parent != nil {
			getPropertiesFromParentPoms(
				ctx, allProperties, *parentPom.Parent.GroupID, *parentPom.Parent.ArtifactID, *parentPom.Parent.Version,
				ArchiveCatalogerConfig{MavenBaseURL: mavenBaseURL}, nil)
		}
		addPropertiesToProject(parentPom, allProperties)
		addMissingPropertiesFromProject(allProperties, parentPom)

		// Store in cache
		parsedPomFilesCache[mavenCoordinate{groupID, artifactID, version}] = parentPom
	}

	return parentPom, err
}

// Try to get the Pom from the users local repository in the users home dir.
// Returns (nil, false) when file cannot be found or read for any reason.
func getPomFromMavenUserLocalRepository(groupID, artifactID, version string, cfg ArchiveCatalogerConfig) (*gopom.Project, bool) {
	localRepoDir, exists := getLocalRepositoryExists(cfg)

	if !exists {
		return nil, false
	}

	groupPath := filepath.Join(strings.Split(groupID, ".")...)
	pomFile := filepath.Join(localRepoDir, groupPath, artifactID, version, artifactID+"-"+version+".pom")

	if _, err := os.Stat(pomFile); !os.IsNotExist(err) {
		log.Debugf("found pom file: %s", pomFile)
		bytes, err := os.ReadFile(pomFile)
		if err != nil {
			log.Errorf("could not read pom file: [%s], error: %w", pomFile, err)
			return nil, false
		}
		pom, err := decodePomXML(strings.NewReader(string(bytes)))
		if err != nil {
			log.Errorf("could not parse pom file: [%s], error: %w", pomFile, err)
			return nil, false
		}
		return &pom, true
	}

	log.Debugf("could not find pom file: [%s]", pomFile)

	return nil, false
}

// Get Maven local repository of current user, if it exists. Only checks once and store the result in 'mavenLocalRepoDir'.
func getLocalRepositoryExists(cfg ArchiveCatalogerConfig) (string, bool) {
	found := false
	if checkedForMavenLocalRepo {
		if mavenLocalRepoDir != "" {
			// dir was found in previous call of this function
			found = true
		}
		return mavenLocalRepoDir, found
	}

	localRepoDir := cfg.MavenLocalRepositoryDir
	if _, err := os.Stat(localRepoDir); !os.IsNotExist(err) {
		mavenLocalRepoDir = localRepoDir
		found = true
	} else {
		log.Warnf("local Maven repository not found at [%s],", localRepoDir)
	}
	checkedForMavenLocalRepo = true

	return mavenLocalRepoDir, found
}

// Get default location of the Maven local repository at <USER HOME DIR>/.m2/repository
func getDefaultMavenLocalRepoLocation() (string, error) {
	homeDir, err := os.UserHomeDir()

	if err != nil {
		return "", err
	}
	localRepoDir := filepath.Join(homeDir, ".m2", "repository")
	if _, err := os.Stat(homeDir); !os.IsNotExist(err) {
		return localRepoDir, nil
	}
	return "", fmt.Errorf("local Maven repository not found at default location [%s],", localRepoDir)
}

// Download the pom file from a (remote) Maven repository over HTTP.
func getPomFromMavenRepo(ctx context.Context, groupID, artifactID, version, mavenBaseURL string) (*gopom.Project, error) {
	if len(groupID) == 0 || len(artifactID) == 0 || !isPropertyResolved(version) {
		return nil, fmt.Errorf("missing/incomplete maven artifact coordinates: groupId:artifactId:version = %s:%s:%s", groupID, artifactID, version)
	}
	// Downloading snapshots requires additional steps to determine the latest snapshot version.
	// See: https://maven.apache.org/ref/3-LATEST/maven-repository-metadata/
	if strings.HasSuffix(version, "-SNAPSHOT") {
		return nil, fmt.Errorf("downloading snapshot artifacts is not supported: groupId:artifactId:version = %s:%s:%s", groupID, artifactID, version)
	}

	requestURL, err := formatMavenPomURL(groupID, artifactID, version, mavenBaseURL)
	if err != nil {
		return nil, err
	}
	log.Tracef("trying to fetch parent pom from Maven repository %s", requestURL)

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
		return nil, fmt.Errorf("unable to get pom from Maven repository: %w", err)
	}
	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("pom not found in Maven repository")
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Errorf("unable to close body: %+v", err)
		}
	}()

	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to parse pom from Maven repository: %w", err)
	}

	pom, err := decodePomXML(strings.NewReader(string(bytes)))
	if err != nil {
		return nil, fmt.Errorf("unable to parse pom from Maven repository: %w", err)
	}
	log.Tracef("fetched parent pom from Maven repository.")
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

// Returns all dependencies in a project, including all defined in profiles.
func getPomDependencies(pom *gopom.Project) *[]gopom.Dependency {
	var dependencies []gopom.Dependency = make([]gopom.Dependency, 0)
	if pom.Profiles != nil && len(*pom.Profiles) > 0 {
		// Gather dependencies from profiles and main dependencies
		if pom.Dependencies != nil {
			dependencies = append(dependencies, *pom.Dependencies...)
		}

		for _, profile := range *pom.Profiles {
			if profile.Dependencies != nil {
				dependencies = append(dependencies, *profile.Dependencies...)
			}
		}
		return &dependencies
	}

	if pom.Dependencies != nil {
		return pom.Dependencies
	}

	return &dependencies
}

// Returns all managed dependencies in a project, including all defined in profiles.
func getPomManagedDependencies(pom *gopom.Project) *[]gopom.Dependency {
	if pom.Profiles != nil && len(*pom.Profiles) > 0 {
		var mDependencies []gopom.Dependency = make([]gopom.Dependency, 0)
		if pom.DependencyManagement != nil && pom.DependencyManagement.Dependencies != nil {
			mDependencies = append(mDependencies, *pom.DependencyManagement.Dependencies...)
		}

		for _, profile := range *pom.Profiles {
			if profile.DependencyManagement != nil && profile.DependencyManagement.Dependencies != nil {
				mDependencies = append(mDependencies, *profile.DependencyManagement.Dependencies...)
			}
		}
		return &mDependencies
	}

	if pom.DependencyManagement != nil && pom.DependencyManagement.Dependencies != nil {
		return pom.DependencyManagement.Dependencies
	}

	var mDependencies []gopom.Dependency = make([]gopom.Dependency, 0)
	return &mDependencies
}

// Traverse the parent pom hierarchy and return all found properties.
// To be used for resolving property references later on while determining versions.
// This function recursively processes each encountered parent pom until no parent pom
// is found.
func getPropertiesFromParentPoms(ctx context.Context, allProperties map[string]string, parentGroupID, parentArtifactID, parentVersion string,
	cfg ArchiveCatalogerConfig, parsedPomFiles map[mavenCoordinate]bool) {
	// Create map to keep track of parsed pom files and to prevent cycles.
	if parsedPomFiles == nil {
		parsedPomFiles = make(map[mavenCoordinate]bool)
	}
	log.Debugf("recursively gathering all properties from pom [%s, %s, %s], recursion depth: %d",
		parentGroupID, parentArtifactID, parentVersion, len(parsedPomFiles))

	pomCoordinates := mavenCoordinate{parentGroupID, parentArtifactID, parentVersion}
	_, alreadyParsed := parsedPomFiles[pomCoordinates]
	if alreadyParsed {
		// Nothing new here, already parsed
		log.Debug("skipping already processed pom.")
		return
	}

	parentPom, err := getPomFromCacheOrMaven(ctx, parentGroupID, parentArtifactID, parentVersion, allProperties, cfg)

	if err == nil {
		if parentPom != nil {
			parsedPomFiles[pomCoordinates] = true
			addMissingPropertiesFromProject(allProperties, parentPom)

			// recurse into another parent pom
			if parentPom.Parent != nil {
				getPropertiesFromParentPoms(ctx, allProperties, *parentPom.GroupID, *parentPom.ArtifactID, *parentPom.Version,
					cfg, parsedPomFiles)
			}
		} else {
			log.Errorf("got empty parent pom, error: %w")
		}
	} else {
		log.Errorf("could not get parent pom: %w", err)
	}
}

// Resolve references to properties (e.g. '${prop.name}') recursively by searching entries in 'allProperties'.
func resolveRecursiveByPropertyName(pomProperties map[string]string, propertyName string) string {
	if strings.HasPrefix(propertyName, "${") {
		name := getPropertyName(propertyName)
		if value, ok := pomProperties[name]; ok {
			if strings.HasPrefix(value, "${") {
				return resolveRecursiveByPropertyName(pomProperties, value)
			}
			return value
		}
	}
	return propertyName
}

// If 'value' is a property reference (e.g. '${prop.name}'), return the property name (e.g. prop.name).
// Otherwise return the given 'value'
func getPropertyName(value string) string {
	propertyName := value
	if strings.HasPrefix(propertyName, "${") {
		propertyName = strings.TrimSpace(propertyName[2 : len(propertyName)-1]) // remove leading ${ and trailing }
	}
	return propertyName
}

// Add all properties from the project 'pom' to the map 'allProperties' that are not already in the map.
func addMissingPropertiesFromProject(allProperties map[string]string, pom *gopom.Project) {
	if pom != nil && pom.Properties != nil && pom.Properties.Entries != nil {
		for name := range pom.Properties.Entries {
			// Add property from pom that is not yet in allProperties map.
			_, exists := allProperties[name]
			if !exists {
				currentValue := pom.Properties.Entries[name]
				value := resolveProperty(*pom, &currentValue, getPropertyName(currentValue))
				allProperties[name] = value
				// log.Tracef("added property ['%s'='%s'] from pom [%s, %s, %s] to allProperties", name, value,
				// 	*pom.GroupID, *pom.ArtifactID, *pom.Version)
			}
		}
		// Try to resolve any added properties containing property references.
		for name, value := range allProperties {
			if strings.HasPrefix(value, "${") {
				allProperties[name] = resolveRecursiveByPropertyName(allProperties, value)
			}
		}
	}
}

// Add all properties from map 'allProperties' to the project 'pom' that are not already defined in the pom.
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
				pom.Properties.Entries[name] = value
				// log.Tracef("added property ['%s'='%s'] to pom [%s, %s, %s]", name, value, *pom.GroupID, *pom.ArtifactID, *pom.Version)
			}
		}
	}
}
