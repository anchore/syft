package java

import (
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/cpegenerate"
)

// PackageURL returns the PURL for the specific java package (see https://github.com/package-url/purl-spec)
func packageURL(name, version string, metadata pkg.JavaArchive) string {
	var groupID = name

	if gID := groupIDFromJavaMetadata(name, metadata); gID != "" {
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

// GroupIDFromJavaPackage returns the authoritative group ID for a Java package.
// The order of precedence is:
// 1. The group ID from the POM properties
// 2. The group ID from the POM project
// 3. The group ID from a select map of known group IDs
// 4. The group ID from the Java manifest
func groupIDFromJavaMetadata(pkgName string, metadata pkg.JavaArchive) (groupID string) {
	if groupID = groupIDFromPomProperties(metadata.PomProperties); groupID != "" {
		return groupID
	}

	if groupID = groupIDFromPomProject(metadata.PomProject); groupID != "" {
		return groupID
	}

	if groupID = groupIDFromKnownPackageList(pkgName); groupID != "" {
		return groupID
	}

	if groupID = groupIDFromJavaManifest(metadata.Manifest); groupID != "" {
		return groupID
	}

	return groupID
}

func groupIDFromKnownPackageList(pkgName string) (groupID string) {
	if groupID, ok := cpegenerate.DefaultArtifactIDToGroupID[pkgName]; ok {
		return groupID
	}
	return groupID
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
