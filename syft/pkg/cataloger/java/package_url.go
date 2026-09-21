package java

import (
	"strconv"
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/cpegenerate"
)

// PackageURL returns the PURL for the specific java package (see https://github.com/package-url/purl-spec)
func packageURL(name, version string, metadata pkg.JavaArchive) string {
	var groupID = name

	if gID := groupIDFromJavaMetadata(name, version, metadata); gID != "" {
		groupID = gID
	}

	pURL := packageurl.NewPackageURL(
		packageurl.TypeMaven, // TODO: should we filter down by package types here?
		groupID,
		name,
		version,
		nil, // TODO: there are probably several qualifiers that can be specified here
		"")
	return pURL.ToString()
}

// groupIDFromJavaMetadata returns the authoritative group ID for a Java package.
// The order of precedence is:
// 1. The group ID from the POM properties
// 2. The group ID from the POM project
// 3. A major-version group ID migration, when one applies
// 4. The group ID from a select map of known group IDs
// 5. The group ID from the Java manifest
func groupIDFromJavaMetadata(pkgName, version string, metadata pkg.JavaArchive) (groupID string) {
	if groupID = groupIDFromPomProperties(metadata.PomProperties); groupID != "" {
		return groupID
	}

	if groupID = groupIDFromPomProject(metadata.PomProject); groupID != "" {
		return groupID
	}

	if groupID = groupIDFromKnownPackageList(pkgName, version); groupID != "" {
		return groupID
	}

	if groupID = groupIDFromJavaManifest(metadata.Manifest); groupID != "" {
		return groupID
	}

	return groupID
}

// javaGroupIDMigrations records artifact families whose published group ID
// changed with a new major version. The static cpegenerate.DefaultArtifactIDToGroupID
// map keeps the historical coordinates, so when that map attributes an artifact to
// the migration's previous group ID, the listed major version and newer resolve to
// the new group instead. Groovy 4.0 (2022) moved from the Codehaus coordinates
// (org.codehaus.groovy) to the Apache Software Foundation (org.apache.groovy); the
// Eclipse-hosted groovy-eclipse-* artifacts share the prefix but kept their Codehaus
// coordinates, so they are excluded.
var javaGroupIDMigrations = []struct {
	artifactPrefix string
	excludePrefix  string
	previousGroup  string
	fromMajor      int
	groupID        string
}{
	{
		artifactPrefix: "groovy",
		excludePrefix:  "groovy-eclipse",
		previousGroup:  "org.codehaus.groovy",
		fromMajor:      4,
		groupID:        "org.apache.groovy",
	},
}

func groupIDFromKnownPackageList(pkgName, version string) (groupID string) {
	knownGroupID, known := cpegenerate.DefaultArtifactIDToGroupID[pkgName]
	if !known {
		return ""
	}

	for _, migration := range javaGroupIDMigrations {
		if strings.HasPrefix(pkgName, migration.artifactPrefix) &&
			(migration.excludePrefix == "" || !strings.HasPrefix(pkgName, migration.excludePrefix)) &&
			knownGroupID == migration.previousGroup &&
			majorVersion(version) >= migration.fromMajor {
			return migration.groupID
		}
	}

	return knownGroupID
}

// majorVersion extracts the leading numeric component of a dotted version
// (for example "4.0.33" resolves to 4). It returns 0 when the version does not
// start with a number.
func majorVersion(version string) int {
	leading, _, _ := strings.Cut(version, ".")
	n, err := strconv.Atoi(leading)
	if err != nil {
		return 0
	}
	return n
}

func groupIDFromJavaManifest(manifest *pkg.JavaManifest) (groupID string) {
	if manifest == nil {
		return groupID
	}

	groupIDs := cpegenerate.GetManifestFieldGroupIDs(manifest, cpegenerate.PrimaryJavaManifestGroupIDFields)
	// assumes that primaryJavaManifestNameFields are ordered by priority
	if len(groupIDs) != 0 {
		return groupIDs[0]
	}

	groupIDs = cpegenerate.GetManifestFieldGroupIDs(manifest, cpegenerate.SecondaryJavaManifestGroupIDFields)

	if len(groupIDs) != 0 {
		return groupIDs[0]
	}

	return groupID
}

func groupIDFromPomProperties(properties *pkg.JavaPomProperties) (groupID string) {
	if properties == nil {
		return groupID
	}

	if properties.GroupID != "" {
		return cleanGroupID(properties.GroupID)
	}

	// sometimes the publisher puts the group ID in the artifact ID field unintentionally
	if looksLikeGroupID(properties.ArtifactID) {
		// there is a strong indication that the artifact ID is really a group ID
		return cleanGroupID(properties.ArtifactID)
	}

	return groupID
}

func groupIDFromPomProject(project *pkg.JavaPomProject) (groupID string) {
	if project == nil {
		return groupID
	}

	// check the project details
	if project.GroupID != "" {
		return cleanGroupID(project.GroupID)
	}

	// sometimes the publisher puts the group ID in the artifact ID field unintentionally
	if looksLikeGroupID(project.ArtifactID) {
		// there is a strong indication that the artifact ID is really a group ID
		return cleanGroupID(project.ArtifactID)
	}

	// let's check the parent details
	// if the current project does not have a group ID, but the parent does, we'll use the parent's group ID
	if project.Parent != nil {
		if project.Parent.GroupID != "" {
			return cleanGroupID(project.Parent.GroupID)
		}

		// sometimes the publisher puts the group ID in the artifact ID field unintentionally
		if looksLikeGroupID(project.Parent.ArtifactID) {
			// there is a strong indication that the artifact ID is really a group ID
			return cleanGroupID(project.Parent.ArtifactID)
		}
	}

	return groupID
}
func looksLikeGroupID(value string) bool {
	return strings.Contains(value, ".")
}

func cleanGroupID(groupID string) string {
	return strings.TrimSpace(removeOSCIDirectives(groupID))
}

func removeOSCIDirectives(groupID string) string {
	// for example:
	// 		org.bar;uses:=“org.foo”		-> 	org.bar
	// more about OSGI directives see https://spring.io/blog/2008/10/20/understanding-the-osgi-uses-directive/
	return strings.Split(groupID, ";")[0]
}
