package java

import (
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/pkg"
	javaCataloger "github.com/anchore/syft/syft/pkg/cataloger/java"
	"github.com/anchore/syft/syft/sbom"
)

// ResolveHierarchicalDependencies runs after all catalogers have completed. It resolves
// deferred parent IDs in Java dependency relationships and enriches depth/scope from
// the Maven dependency tree when available.
func ResolveHierarchicalDependencies(accessor sbomsync.Accessor, cfg cataloging.RelationshipsConfig) {
	if cfg.JavaMavenDependencyTreeFile == "" {
		// No tree file configured — nothing to resolve or enrich.
		// Deferred parent IDs (IntendedParentID) are only set when a dependency graph
		// was built during cataloging, which requires either a tree file or embedded POMs.
		// Even if embedded POMs were used, the enrichment in Phase 3 has already occurred.
		// This post-processor only adds value when a tree file is available for global enrichment.
		return
	}

	// Step 1: Build package index from ALL Java packages
	pkgIndex := buildPackageIndex(accessor)
	if len(pkgIndex) == 0 {
		return
	}

	// Step 2: Build dependency graph from Maven tree file
	depGraph := buildGraphFromTreeFile(cfg.JavaMavenDependencyTreeFile)

	// Step 3: Process relationships
	var updatedRelationships []artifact.Relationship
	var rootPkg *pkg.Package

	accessor.ReadFromSBOM(func(s *sbom.SBOM) {
		// Find root package (the one that matches the graph root)
		if depGraph != nil && depGraph.Root != nil {
			rootID := depGraph.Root.ID
			rootKey := javaCataloger.NewMavenID(rootID.GroupID, rootID.ArtifactID, rootID.Version).String()
			rootPkg = findPackageByMavenID(pkgIndex, rootKey)
		}

		for _, rel := range s.Relationships {
			newRel := processRelationship(rel, s.Artifacts.Packages, pkgIndex, depGraph, rootPkg)
			updatedRelationships = append(updatedRelationships, newRel)
		}
	})

	// Step 4: Write updated relationships back
	accessor.WriteToSBOM(func(s *sbom.SBOM) {
		s.Relationships = updatedRelationships
	})
}

// buildPackageIndex creates a multi-tier index of Java packages for flexible matching.
// Packages are indexed by:
// - Full Maven ID: groupId:artifactId:version (exact)
// - groupId:artifactId (version-flexible)
// - artifactId only (last resort)
func buildPackageIndex(accessor sbomsync.Accessor) map[string]*pkg.Package {
	pkgIndex := make(map[string]*pkg.Package)

	accessor.ReadFromSBOM(func(s *sbom.SBOM) {
		for p := range s.Artifacts.Packages.Enumerate(pkg.JavaPkg, pkg.JenkinsPluginPkg) {
			pCopy := p
			mavenID := extractMavenID(&pCopy)
			if mavenID == "" {
				continue
			}

			// Tier 1: full Maven ID (exact match — highest priority, never overwritten)
			if _, exists := pkgIndex[mavenID]; !exists {
				pkgIndex[mavenID] = &pCopy
			}

			// Tier 2: groupId:artifactId (version-flexible)
			gaKey := extractGroupArtifact(mavenID)
			if gaKey != "" {
				if _, exists := pkgIndex[gaKey]; !exists {
					pkgIndex[gaKey] = &pCopy
				}
			}

			// Tier 3: artifactId only (last resort)
			artifactID := extractArtifactID(mavenID)
			if artifactID != "" {
				if _, exists := pkgIndex[artifactID]; !exists {
					pkgIndex[artifactID] = &pCopy
				}
			}
		}
	})

	return pkgIndex
}

// buildGraphFromTreeFile parses a Maven dependency tree file and returns a DependencyGraph.
func buildGraphFromTreeFile(filePath string) *javaCataloger.DependencyGraph {
	tree, err := javaCataloger.ParseMavenDependencyTreeFile(filePath)
	if err != nil {
		log.WithFields("error", err, "file", filePath).Warn("failed to parse Maven dependency tree file for post-processing")
		return nil
	}
	return tree.ToInternalGraph()
}

// processRelationship handles a single relationship, applying the three processing cases.
func processRelationship(
	rel artifact.Relationship,
	packages *pkg.Collection,
	pkgIndex map[string]*pkg.Package,
	depGraph *javaCataloger.DependencyGraph,
	rootPkg *pkg.Package,
) artifact.Relationship {
	// Only process DependencyOf relationships
	if rel.Type != artifact.DependencyOfRelationship {
		return rel
	}

	// Only process relationships where "From" is a Java package
	fromPkg := packages.Package(rel.From.ID())
	if fromPkg == nil {
		return rel
	}
	if fromPkg.Language != pkg.Java {
		return rel
	}

	relData, hasRelData := rel.Data.(javaCataloger.DependencyRelationshipData)

	// Case 1: Has IntendedParentID — resolve deferred parent
	if hasRelData && relData.IntendedParentID != "" {
		return resolveIntendedParent(rel, relData, fromPkg, pkgIndex, depGraph, rootPkg)
	}

	// Case 2: No IntendedParentID, but depGraph exists — enrich from tree
	if depGraph != nil {
		return enrichFromGraph(rel, fromPkg, depGraph)
	}

	// Case 3: No tree or not found — keep original
	return rel
}

// resolveIntendedParent handles Case 1: the relationship has a deferred IntendedParentID.
func resolveIntendedParent(
	rel artifact.Relationship,
	relData javaCataloger.DependencyRelationshipData,
	fromPkg *pkg.Package,
	pkgIndex map[string]*pkg.Package,
	depGraph *javaCataloger.DependencyGraph,
	rootPkg *pkg.Package,
) artifact.Relationship {
	parentPkg := findPackageByMavenID(pkgIndex, relData.IntendedParentID)

	if parentPkg != nil {
		// Case 1a: Parent found — resolve and enrich
		depth := relData.Depth
		scope := relData.Scope

		if depGraph != nil {
			mavenID := extractMavenIDStruct(fromPkg)
			if node := depGraph.FindNodeByMavenID(mavenID); node != nil {
				depth = node.Depth - 1
				if depth < 0 {
					depth = 0
				}
				scope = node.Scope
			}
		}

		rel.To = *parentPkg
		rel.Data = javaCataloger.NewDependencyRelationshipData(depth, scope)
		return rel
	}

	// Case 1b: Parent NOT found — skip to nearest ancestor
	if depGraph != nil {
		parentMavenID := parseMavenID(relData.IntendedParentID)
		parentNode := depGraph.FindNodeByMavenID(parentMavenID)
		if ancestorPkg := findNearestAncestorInSBOM(parentNode, pkgIndex, rootPkg); ancestorPkg != nil {
			rel.To = *ancestorPkg
		}
	}

	// Clear IntendedParentID — resolution attempted
	depth := relData.Depth
	scope := relData.Scope
	rel.Data = javaCataloger.NewDependencyRelationshipData(depth, scope)
	return rel
}

// enrichFromGraph handles Case 2: no IntendedParentID but a dependency graph is available.
func enrichFromGraph(
	rel artifact.Relationship,
	fromPkg *pkg.Package,
	depGraph *javaCataloger.DependencyGraph,
) artifact.Relationship {
	mavenID := extractMavenIDStruct(fromPkg)
	if !mavenID.Valid() {
		return rel
	}

	node := depGraph.FindNodeByMavenID(mavenID)
	if node == nil {
		return rel
	}

	relDepth := node.Depth - 1
	if relDepth < 0 {
		relDepth = 0
	}

	rel.Data = javaCataloger.NewDependencyRelationshipData(relDepth, node.Scope)
	return rel
}

// findNearestAncestorInSBOM walks up the Maven tree from a missing parent node
// until finding an ancestor whose package IS in the SBOM.
func findNearestAncestorInSBOM(
	missingNode *javaCataloger.DependencyNode,
	pkgIndex map[string]*pkg.Package,
	rootPkg *pkg.Package,
) *pkg.Package {
	if missingNode == nil {
		return rootPkg
	}

	current := missingNode.Parent
	for current != nil {
		ancestorKey := javaCataloger.NewMavenID(current.ID.GroupID, current.ID.ArtifactID, current.ID.Version).String()
		if ancestorPkg := findPackageByMavenID(pkgIndex, ancestorKey); ancestorPkg != nil {
			return ancestorPkg
		}
		current = current.Parent
	}

	return rootPkg
}

// findPackageByMavenID looks up a package using 3-tier flexible matching.
func findPackageByMavenID(pkgIndex map[string]*pkg.Package, mavenID string) *pkg.Package {
	// Tier 1: exact match — groupId:artifactId:version
	if p, ok := pkgIndex[mavenID]; ok {
		return p
	}

	// Tier 2: groupId:artifactId (ignore version)
	gaKey := extractGroupArtifact(mavenID)
	if gaKey != "" {
		if p, ok := pkgIndex[gaKey]; ok {
			return p
		}
	}

	// Tier 3: artifactId only (last resort)
	artifactID := extractArtifactID(mavenID)
	if artifactID != "" {
		if p, ok := pkgIndex[artifactID]; ok {
			return p
		}
	}

	return nil
}

// extractMavenID returns a "groupId:artifactId:version" string from a package's metadata.
func extractMavenID(p *pkg.Package) string {
	if p == nil {
		return ""
	}
	metadata, ok := p.Metadata.(pkg.JavaArchive)
	if !ok {
		return ""
	}

	groupID := ""
	artifactID := p.Name
	version := p.Version

	if metadata.PomProperties != nil {
		if metadata.PomProperties.GroupID != "" {
			groupID = metadata.PomProperties.GroupID
		}
		if metadata.PomProperties.ArtifactID != "" {
			artifactID = metadata.PomProperties.ArtifactID
		}
		if metadata.PomProperties.Version != "" {
			version = metadata.PomProperties.Version
		}
	}

	if groupID == "" && metadata.PomProject != nil {
		groupID = metadata.PomProject.GroupID
	}

	if groupID == "" || artifactID == "" {
		return ""
	}

	return groupID + ":" + artifactID + ":" + version
}

// extractMavenIDStruct returns a MavenID struct for graph lookups.
func extractMavenIDStruct(p *pkg.Package) javaCataloger.MavenID {
	id := extractMavenID(p)
	if id == "" {
		return javaCataloger.MavenID{}
	}
	return parseMavenID(id)
}

// parseMavenID parses a "groupId:artifactId:version" string into a MavenID.
func parseMavenID(mavenID string) javaCataloger.MavenID {
	parts := strings.SplitN(mavenID, ":", 3)
	if len(parts) != 3 {
		return javaCataloger.MavenID{}
	}
	return javaCataloger.NewMavenID(parts[0], parts[1], parts[2])
}

// extractGroupArtifact returns "groupId:artifactId" from a full Maven ID.
func extractGroupArtifact(mavenID string) string {
	parts := strings.SplitN(mavenID, ":", 3)
	if len(parts) < 2 {
		return ""
	}
	return parts[0] + ":" + parts[1]
}

// extractArtifactID returns just the artifactId from a full Maven ID.
func extractArtifactID(mavenID string) string {
	parts := strings.SplitN(mavenID, ":", 3)
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}
