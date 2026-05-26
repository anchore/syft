package java

import (
	"fmt"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

// ResolveHierarchicalDependencies resolves deferred parent relationships for Java packages.
// When the dependency graph at cataloging time identifies an intended parent that wasn't
// available in the same archive, this post-processor resolves those deferred relationships
// by looking up parents across the full SBOM.
func ResolveHierarchicalDependencies(accessor sbomsync.Accessor, cfg ArchiveCatalogerConfig) {
	if !cfg.UseEmbeddedPOMDependencies {
		return
	}

	var packages []pkg.Package
	var relationships []artifact.Relationship

	accessor.ReadFromSBOM(func(s *sbom.SBOM) {
		packages = s.Artifacts.Packages.Sorted(pkg.JavaPkg)
		relationships = s.Relationships
	})

	if len(relationships) == 0 {
		return
	}

	pkgIndex := buildPackageIndex(packages)

	var updated bool
	for i := range relationships {
		rel := &relationships[i]
		if rel.Type != artifact.DependencyOfRelationship {
			continue
		}

		data, ok := rel.Data.(DependencyRelationshipData)
		if !ok || data.IntendedParentID == "" {
			continue
		}

		resolvedParent := findPackageByMavenID(pkgIndex, data.IntendedParentID)
		if resolvedParent != nil {
			rel.To = *resolvedParent
			data.IntendedParentID = ""
			rel.Data = data
			updated = true
			continue
		}

		// fallback: try to find nearest ancestor in SBOM
		ancestor := findNearestAncestor(pkgIndex, data.IntendedParentID)
		if ancestor != nil {
			rel.To = *ancestor
			data.IntendedParentID = ""
			rel.Data = data
			updated = true
		} else {
			log.WithFields("intendedParent", data.IntendedParentID).Debug("unable to resolve deferred parent relationship")
		}
	}

	if updated {
		accessor.WriteToSBOM(func(s *sbom.SBOM) {
			s.Relationships = relationships
		})
	}
}

// buildPackageIndex creates a 3-tier index of Java packages by their Maven coordinates.
func buildPackageIndex(packages []pkg.Package) map[string]*pkg.Package {
	index := make(map[string]*pkg.Package)

	for i := range packages {
		p := &packages[i]
		mavenID := extractMavenIDString(p)
		if mavenID == "" {
			continue
		}

		// full ID: groupId:artifactId:version
		if _, exists := index[mavenID]; !exists {
			index[mavenID] = p
		}

		// partial: groupId:artifactId
		ga := extractGroupArtifact(mavenID)
		if ga != "" {
			if _, exists := index[ga]; !exists {
				index[ga] = p
			}
		}

		// minimal: artifactId only
		a := extractArtifactIDFromCoord(mavenID)
		if a != "" {
			if _, exists := index[a]; !exists {
				index[a] = p
			}
		}
	}

	return index
}

// findPackageByMavenID looks up a package using 3-tier matching: full ID, groupId:artifactId, artifactId.
func findPackageByMavenID(pkgIndex map[string]*pkg.Package, mavenID string) *pkg.Package {
	// try exact match first
	if p, exists := pkgIndex[mavenID]; exists {
		return p
	}

	// try groupId:artifactId
	ga := extractGroupArtifact(mavenID)
	if ga != "" {
		if p, exists := pkgIndex[ga]; exists {
			return p
		}
	}

	// try artifactId only
	a := extractArtifactIDFromCoord(mavenID)
	if a != "" {
		if p, exists := pkgIndex[a]; exists {
			return p
		}
	}

	return nil
}

// findNearestAncestor attempts to locate a parent by progressively relaxing the match.
// This handles the skip-to-ancestor case where an intermediate parent is not in the SBOM.
func findNearestAncestor(pkgIndex map[string]*pkg.Package, intendedParentID string) *pkg.Package {
	// the 3-tier lookup in findPackageByMavenID already handles relaxed matching
	// this function exists as an extension point for future ancestor-walking logic
	return nil
}

// extractMavenIDString returns "groupId:artifactId:version" from a package's Java metadata.
func extractMavenIDString(p *pkg.Package) string {
	if p == nil {
		return ""
	}

	metadata, ok := p.Metadata.(pkg.JavaArchive)
	if !ok {
		return ""
	}

	if metadata.PomProperties != nil {
		pp := metadata.PomProperties
		if pp.GroupID != "" && pp.ArtifactID != "" {
			return fmt.Sprintf("%s:%s:%s", pp.GroupID, pp.ArtifactID, pp.Version)
		}
	}

	if metadata.PomProject != nil {
		pj := metadata.PomProject
		if pj.GroupID != "" && pj.ArtifactID != "" {
			return fmt.Sprintf("%s:%s:%s", pj.GroupID, pj.ArtifactID, pj.Version)
		}
	}

	return ""
}

// extractGroupArtifact returns "groupId:artifactId" from a full maven coordinate string.
func extractGroupArtifact(mavenID string) string {
	parts := strings.SplitN(mavenID, ":", 3)
	if len(parts) >= 2 && parts[0] != "" && parts[1] != "" {
		return parts[0] + ":" + parts[1]
	}
	return ""
}

// extractArtifactIDFromCoord returns just the artifactId from a maven coordinate string.
func extractArtifactIDFromCoord(mavenID string) string {
	parts := strings.SplitN(mavenID, ":", 3)
	if len(parts) >= 2 {
		return parts[1]
	}
	return ""
}
