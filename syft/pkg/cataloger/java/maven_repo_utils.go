package java

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/vifraa/gopom"
)

func remotePomURL(repoURL, groupID, artifactID, version string) (requestURL string, err error) {
	// groupID needs to go from maven.org -> maven/org
	urlPath := strings.Split(groupID, ".")
	artifactPom := fmt.Sprintf("%s-%s.pom", artifactID, version)
	urlPath = append(urlPath, artifactID, version, artifactPom)

	// ex: https://repo1.maven.org/maven2/groupID/artifactID/artifactPom
	requestURL, err = url.JoinPath(repoURL, urlPath...)
	if err != nil {
		return requestURL, fmt.Errorf("could not construct maven url: %w", err)
	}
	return requestURL, err
}

// Try to find the version of a dependency (groupID, artifactID) by searching all parent poms and imported managed dependencies
//
//nolint:gocognit
func (r *mavenResolver) findInheritedVersion(ctx context.Context, root *gopom.Project, pom *gopom.Project, groupID, artifactID string, resolving ...mavenID) (string, error) {
	id := newMavenID(pom.GroupID, pom.ArtifactID, pom.Version)
	if len(resolving) >= r.cfg.MaxParentRecursiveDepth {
		return "", fmt.Errorf("maximum depth reached attempting to resolve version for: %s:%s at: %v", groupID, artifactID, resolving)
	}
	if slices.Contains(resolving, id) {
		return "", fmt.Errorf("cycle detected attempting to resolve version for: %s:%s at: %v", groupID, artifactID, resolving)
	}
	resolving = append(resolving, id)

	var err error
	var version string

	// check for entries in dependencyManagement first
	for _, dep := range directManagedDependencies(pom) {
		depGroupID := r.getPropertyValue(ctx, root, dep.GroupID)
		depArtifactID := r.getPropertyValue(ctx, root, dep.ArtifactID)
		if depGroupID == groupID && depArtifactID == artifactID {
			version = r.getPropertyValue(ctx, root, dep.Version)
			if version != "" {
				return version, nil
			}
		}

		// imported pom files should be treated just like parent poms, they are used to define versions of dependencies
		if deref(dep.Type) == "pom" && deref(dep.Scope) == "import" {
			depVersion := r.getPropertyValue(ctx, root, dep.Version)

			depPom, err := r.findPom(ctx, depGroupID, depArtifactID, depVersion)
			if err != nil {
				return "", err
			}
			version, err = r.findInheritedVersion(ctx, root, depPom, groupID, artifactID, resolving...)
			if err != nil {
				return "", err
			}
			if version != "" {
				return version, nil
			}
		}
	}

	// recursively check parents
	parent, err := r.findParent(ctx, pom)
	if err != nil {
		return "", err
	}
	if parent != nil {
		version, err = r.findInheritedVersion(ctx, root, parent, groupID, artifactID, resolving...)
		if err != nil {
			return "", err
		}
		if version != "" {
			return version, nil
		}
	}

	// check for inherited dependencies
	for _, dep := range directDependencies(pom) {
		depGroupID := r.getPropertyValue(ctx, root, dep.GroupID)
		depArtifactID := r.getPropertyValue(ctx, root, dep.ArtifactID)
		if depGroupID == groupID && depArtifactID == artifactID {
			version = r.getPropertyValue(ctx, root, dep.Version)
			if version != "" {
				return version, nil
			}
		}
	}

	return "", nil
}

// resolveLicenses search pom for license, traversing parent poms if needed. Also returns if a pom file was found in order to differentiate between no pom and no license found.
func (r *mavenResolver) resolveLicenses(ctx context.Context, groupID, artifactID, version string) ([]string, error) {
	pom, err := r.findPom(ctx, groupID, artifactID, version)
	if pom == nil || err != nil {
		return nil, err
	}
	return r.findLicenses(ctx, pom)
}

// Search pom for license, traversing parent poms if needed. Also returns if a pom file was found in order to differentiate between no pom and no license found.
func (r *mavenResolver) findLicenses(ctx context.Context, pom *gopom.Project, processing ...mavenID) ([]string, error) {
	id := makeID(pom)
	if slices.Contains(processing, id) {
		return nil, fmt.Errorf("cycle detected resolving licenses for: %v", id)
	}
	if len(processing) > r.cfg.MaxParentRecursiveDepth {
		return nil, fmt.Errorf("maximum parent recursive depth (%v) reached: %v", r.cfg.MaxParentRecursiveDepth, processing)
	}

	licenses := directLicenses(pom)
	if len(licenses) > 0 {
		return licenses, nil
	}

	parent, err := r.findParent(ctx, pom)
	if err != nil {
		return nil, err
	}
	if parent == nil {
		return nil, nil
	}
	return r.findLicenses(ctx, parent, append(processing, id)...)
}

// func pomDescriptions(ids []mavenID) []string {
//	var out []string
//	for _, id := range ids {
//		out = append(out, id.String())
//	}
//	return out
//}

func makeID(pom *gopom.Project) mavenID {
	if pom == nil {
		return mavenID{}
	}
	return newMavenID(pom.GroupID, pom.ArtifactID, pom.Version)
}

// directLicenses returns the licenses defined directly in the pom
func directLicenses(pom *gopom.Project) []string {
	var licenses []string
	for _, license := range deref(pom.Licenses) {
		if license.Name != nil {
			licenses = append(licenses, *license.Name)
		} else if license.URL != nil {
			licenses = append(licenses, *license.URL)
		}
	}
	return licenses
}

// directDependencies returns all direct dependencies in a project, including all defined in profiles
func directDependencies(pom *gopom.Project) []gopom.Dependency {
	dependencies := deref(pom.Dependencies)
	for _, profile := range deref(pom.Profiles) {
		dependencies = append(dependencies, deref(profile.Dependencies)...)
	}
	return dependencies
}

// directManagedDependencies returns all managed dependencies in a project, including all defined in profiles
func directManagedDependencies(pom *gopom.Project) []gopom.Dependency {
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

// deref dereferences ptr if not nil, or returns the type default value if ptr is nil
func deref[T any](ptr *T) T {
	if ptr == nil {
		var t T
		return t
	}
	return *ptr
}
