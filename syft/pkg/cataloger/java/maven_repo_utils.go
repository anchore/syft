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

func resolveRecursiveByPropertyName(pomProperties map[string]string, propertyName string) string {
	if strings.HasPrefix(propertyName, "${") {
		name := getPropertyName(propertyName)
		// log.Debugf("--Name: %s", name)
		if value, ok := pomProperties[name]; ok {
			// log.Debugf("--Value: %s", value)
			if strings.HasPrefix(value, "${") {
				log.Trace("recurse resolveRecursiveByPropertyName")
				return resolveRecursiveByPropertyName(pomProperties, value)
			} else {
				// log.Debugf("++Value: %s", value)
				return value
			}
		}
		// log.Debugf("**Value: %s", propertyName)
		return propertyName
	} else {
		// log.Debugf("&&Value: %s", propertyName)
		return propertyName
	}
}

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
		for name, value := range pom.Properties.Entries {
			_, exists := allProperties[name]
			if !exists {
				value = resolveProperty(*pom, &value, getPropertyName(value))
				allProperties[name] = value
				log.Tracef("  Added from project, property %s=%s to allProperties", name, value)
			}
		}
		// resolve
		for name, value := range allProperties {
			if strings.HasPrefix(value, "${") {
				allProperties[name] = resolveRecursiveByPropertyName(allProperties, value)
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
				allProperties[name] = value
				// log.Tracef("  Added property %s=%s to pom [%s, %s, %s]", name, value, *pom.GroupID, *pom.ArtifactID, *pom.Version)
			}
		}
	}
}

// Traverse the parent pom hierarchy and return all found properties.
// To be used for resolving property variables.
func getPropertiesFromParentPoms(ctx context.Context, allProperties map[string]string, parentGroupID, parentArtifactID, parentVersion string,
	cfg ArchiveCatalogerConfig, parsedPomFiles map[MavenCoordinate]bool) {
	log.Debugf("Recursively gathering all properties from pom [%s, %s, %s]", parentGroupID, parentArtifactID, parentVersion)

	// Create map to keep track of parsed pom files and to prevent cycles.
	if parsedPomFiles == nil {
		parsedPomFiles = make(map[MavenCoordinate]bool)
	}
	log.Tracef("Recursion depth: %+v", len(parsedPomFiles))

	pomCoordinates := MavenCoordinate{parentGroupID, parentArtifactID, parentVersion}
	_, alreadyParsed := parsedPomFiles[pomCoordinates]
	if alreadyParsed {
		// Nothing new here, already parsed
		log.Info("1 Nothing new here, already processed.")
		return
	}

	parentPom, err := getPomFromMavenOrCache(ctx, parentGroupID, parentArtifactID, parentVersion, allProperties, cfg)

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
			log.Error("Got empty parent pom, error: %w")
		}
	} else {
		log.Errorf("Could not get parent pom: %w", err)
	}
}

// Try to find the version of a dependency (groupID, artifactID) by parsing all parent poms and imported managed dependencies (maven BOMs).
// Properties are gathered in the order that they are encountered: in Maven the latest definition of a property (highest in hierarchy) is used.
// parsedPomFiles contains all previously parsed pom files encountered by earlier invocations of this function on the stack. So for the first
// call parsedPomFiles should be nil. It is used to prevent cycles (endless loops).
func recursivelyFindVersionFromManagedOrInherited(ctx context.Context, findGroupID, findArtifactID string,
	pom *gopom.Project, cfg ArchiveCatalogerConfig, allProperties map[string]string, parsedPomFiles map[MavenCoordinate]bool) string {

	log.Debugf("Recursively finding version from managed or inherited dependencies for dependency [%v:%v] in pom [%s, %s, %s]",
		findGroupID, findArtifactID, *pom.GroupID, *pom.ArtifactID, *pom.Version)

	// Create map to keep track of parsed pom files and to prevent cycles.
	if parsedPomFiles == nil {
		parsedPomFiles = make(map[MavenCoordinate]bool)
	}
	log.Tracef("Recursion depth: %+v", len(parsedPomFiles))

	pomCoordinates := MavenCoordinate{*pom.GroupID, *pom.ArtifactID, *pom.Version}
	_, alreadyParsed := parsedPomFiles[pomCoordinates]
	if alreadyParsed {
		// Nothing new here, already parsed
		log.Info("2 Nothing new here, already processed.")
		return ""
	} else {
		parsedPomFiles[pomCoordinates] = true
	}
	addMissingPropertiesFromProject(allProperties, pom)

	foundVersion := ""
	if pom.DependencyManagement != nil {
		foundVersion = findVersionInDependencyManagement(
			ctx, findGroupID, findArtifactID, pom, cfg, allProperties, parsedPomFiles)
	}
	if isPropertyResolved(foundVersion) {
		return foundVersion
	}

	// If a parent exists, search it recursively.
	if pom.Parent != nil {
		parentGroupID := *pom.Parent.GroupID
		parentArtifactID := *pom.Parent.ArtifactID
		parentVersion := *pom.Parent.Version

		parentPom, err := getPomFromMavenOrCache(ctx, parentGroupID, parentArtifactID, parentVersion, allProperties, cfg)

		if parentPom != nil {
			log.Infof("Found a parent pom: [%s, %s, %s]", *parentPom.GroupID, *parentPom.ArtifactID, *parentPom.Version)
			addMissingPropertiesFromProject(allProperties, parentPom)
			addPropertiesToProject(parentPom, allProperties)
			foundVersion = recursivelyFindVersionFromManagedOrInherited(
				ctx, findGroupID, findArtifactID, parentPom, cfg, allProperties, parsedPomFiles)
		} else {
			log.Warnf("unable to get parent pom [%s, %s, %s]: %v",
				parentGroupID, parentArtifactID, parentVersion, err)
		}
	}

	if foundVersion == "" {
		log.Infof("No version found for dependency: [%s, %s]", findGroupID, findArtifactID)
	} else {
		log.Infof("2Found version [%s] for dependency: [%s, %s]", foundVersion, findGroupID, findArtifactID)
	}
	return foundVersion
}

// Returns true when value is not empty and does not start with "${" (contains an unresolved property).
func isPropertyResolved(value string) bool {
	return value != "" && !strings.HasPrefix(value, "${}")
}

// Get a parent pom from cache or download from a Maven repository
func getPomFromMavenOrCache(ctx context.Context, parentGroupID, parentArtifactID, parentVersion string, allProperties map[string]string,
	cfg ArchiveCatalogerConfig) (*gopom.Project, error) {
	var err error = nil
	parentPom, found := parsedPomFilesCache[MavenCoordinate{parentGroupID, parentArtifactID, parentVersion}]

	if !found && cfg.UseNetwork {
		parentPom, err = getPomFromMavenRepo(ctx, parentGroupID, parentArtifactID, parentVersion, cfg.MavenBaseURL)
		if err == nil {
			addPropertiesToProject(parentPom, allProperties)
			addMissingPropertiesFromProject(allProperties, parentPom)
			// Store in cache
			parsedPomFilesCache[MavenCoordinate{parentGroupID, parentArtifactID, parentVersion}] = parentPom
		}
	}
	return parentPom, err
}

// Find given dependency (groupID, artifactID) in the dependencyManagement section of project 'pom'.
// May recursively call recursivelyFindVersionFromManagedOrInherited when a Maven BOM is found.
func findVersionInDependencyManagement(ctx context.Context, findGroupID, findArtifactID string,
	pom *gopom.Project, cfg ArchiveCatalogerConfig, allProperties map[string]string, parsedPomFiles map[MavenCoordinate]bool) string {

	for _, dependency := range *getPomManagedDependencies(pom) {
		log.Tracef("  Found managed dependency:  [%s, %s, %s]",
			safeString(dependency.GroupID), safeString(dependency.ArtifactID), safeString(dependency.Version))

		// imported pom files should be treated just like parent poms, they are use to define versions of dependencies
		if dependency.Type != nil && dependency.Scope != nil &&
			*dependency.Type == "pom" && *dependency.Scope == "import" {

			bomVersion := resolveProperty(*pom, dependency.Version, getPropertyName(*dependency.Version))
			log.Debugf("Found BOM: [%s, %s, %s]", *dependency.GroupID, *dependency.ArtifactID, bomVersion)
			// Recurse into BOM, which should be treated just like a parent pom
			bomProject, err := getPomFromMavenOrCache(ctx, *dependency.GroupID, *dependency.ArtifactID, bomVersion, allProperties, cfg)
			if err == nil {
				foundVersion := recursivelyFindVersionFromManagedOrInherited(
					ctx, findGroupID, findArtifactID, bomProject, cfg, allProperties, parsedPomFiles)

				log.Info("return 2")
				log.Debugf("Finished processing BOM: [%s, %s, %s], found version: [%s]", *dependency.GroupID, *dependency.ArtifactID, bomVersion, foundVersion)

				addMissingPropertiesFromProject(allProperties, pom)

				if isPropertyResolved(foundVersion) {
					return foundVersion
				}
				if foundVersion != "" {
					foundVersion = resolveProperty(*pom, dependency.Version, "version")
					if foundVersion != "" && !strings.HasPrefix(foundVersion, "${") {
						log.Tracef("Found version for managed dependency in BOM: [%s, %s, %s]", findGroupID, findArtifactID, foundVersion)
						return foundVersion
					}
				}
			}

		} else if *dependency.GroupID == findGroupID && *dependency.ArtifactID == findArtifactID {
			if strings.HasPrefix(*dependency.Version, "${") {

			}
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

	for _, dependency := range *getPomDependencies(pom) {
		if *dependency.GroupID == groupID && *dependency.ArtifactID == artifactID {
			depVersion := resolveProperty(*pom, dependency.Version, getPropertyName(*dependency.Version))
			// TODO: -> trace
			log.Infof("Found dependency: [%s, %s, %s]", *dependency.GroupID, *dependency.ArtifactID, depVersion)
			return depVersion
		}
	}
	log.Tracef("Dependency not found in dependencies")
	return ""
}

func recursivelyFindLicensesFromParentPom(ctx context.Context, groupID, artifactID, version string, cfg ArchiveCatalogerConfig) []string {
	return make([]string, 0)
	log.Debugf("recursively finding license from parent Pom for artifact [%v:%v], using parent pom: [%v:%v:%v]",
		groupID, artifactID, groupID, artifactID, version)
	var licenses []string
	// As there can be nested parent poms, we'll recursively check for licenses until we reach the max depth
	for i := 0; i < cfg.MaxParentRecursiveDepth; i++ {
		parentPom, err := getPomFromMavenRepo(ctx, groupID, artifactID, version, cfg.MavenBaseURL)
		if err != nil {
			// We don't want to abort here as the parent pom might not exist in Maven Central, we'll just log the error
			log.Tracef("unable to get parent pom from Maven repository: %v", err)
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

	} else {
		if pom.Dependencies != nil {
			return pom.Dependencies
		} else {
			return &dependencies
		}
	}
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

	} else {
		if pom.DependencyManagement != nil && pom.DependencyManagement.Dependencies != nil {
			return pom.DependencyManagement.Dependencies
		} else {
			var mDependencies []gopom.Dependency = make([]gopom.Dependency, 0)
			return &mDependencies
		}
	}
}
