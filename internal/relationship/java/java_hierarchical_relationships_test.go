package java

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/pkg"
	javaCataloger "github.com/anchore/syft/syft/pkg/cataloger/java"
	"github.com/anchore/syft/syft/sbom"
)

func newTestSBOM(packages []pkg.Package, relationships []artifact.Relationship) *sbom.SBOM {
	s := &sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages: pkg.NewCollection(),
		},
	}
	s.Artifacts.Packages.Add(packages...)
	s.Relationships = relationships
	return s
}

func javaPkg(groupID, artifactID, version string) pkg.Package {
	p := pkg.Package{
		Name:     artifactID,
		Version:  version,
		Language: pkg.Java,
		Type:     pkg.JavaPkg,
		Metadata: pkg.JavaArchive{
			PomProperties: &pkg.JavaPomProperties{
				GroupID:    groupID,
				ArtifactID: artifactID,
				Version:    version,
			},
		},
	}
	p.SetID()
	return p
}

func depOfRel(from, to pkg.Package, data interface{}) artifact.Relationship {
	return artifact.Relationship{
		From: from,
		To:   to,
		Type: artifact.DependencyOfRelationship,
		Data: data,
	}
}

func TestResolveHierarchicalDependencies_NoTreeFile(t *testing.T) {
	root := javaPkg("com.example", "root", "1.0")
	child := javaPkg("org.dep", "child", "2.0")

	rel := depOfRel(child, root, nil)
	s := newTestSBOM([]pkg.Package{root, child}, []artifact.Relationship{rel})

	builder := sbomsync.NewBuilder(s)
	accessor := builder.(sbomsync.Accessor)

	ResolveHierarchicalDependencies(accessor, cataloging.RelationshipsConfig{})

	// No tree file — should be unchanged
	assert.Len(t, s.Relationships, 1)
	assert.Nil(t, s.Relationships[0].Data)
}

func TestResolveHierarchicalDependencies_WithTreeFile(t *testing.T) {
	root := javaPkg("com.example", "my-app", "1.0.0")
	springCore := javaPkg("org.springframework", "spring-core", "6.2.15")
	springJcl := javaPkg("org.springframework", "spring-jcl", "6.2.15")

	// Flat relationships: both point to root (simulating pre-fix behavior)
	rel1 := depOfRel(springCore, root, nil)
	rel2 := depOfRel(springJcl, root, nil)
	s := newTestSBOM(
		[]pkg.Package{root, springCore, springJcl},
		[]artifact.Relationship{rel1, rel2},
	)

	builder := sbomsync.NewBuilder(s)
	accessor := builder.(sbomsync.Accessor)

	ResolveHierarchicalDependencies(accessor, cataloging.RelationshipsConfig{
		JavaMavenDependencyTreeFile: "../../../syft/pkg/cataloger/java/testdata/maven-dependency-tree.txt",
	})

	require.Len(t, s.Relationships, 2)

	// spring-core should be enriched as direct (depth=0)
	data1, ok := s.Relationships[0].Data.(javaCataloger.DependencyRelationshipData)
	require.True(t, ok)
	assert.Equal(t, 0, data1.Depth)
	assert.True(t, data1.IsDirectDependency)
	assert.Equal(t, "compile", data1.Scope)

	// spring-jcl should be enriched as transitive (depth=1)
	data2, ok := s.Relationships[1].Data.(javaCataloger.DependencyRelationshipData)
	require.True(t, ok)
	assert.Equal(t, 1, data2.Depth)
	assert.False(t, data2.IsDirectDependency)
	assert.Equal(t, "compile", data2.Scope)
}

func TestResolveIntendedParent_ParentFound(t *testing.T) {
	root := javaPkg("com.example", "root", "1.0")
	parent := javaPkg("org.dep", "parent-lib", "2.0")
	child := javaPkg("org.dep", "child-lib", "3.0")

	// child has IntendedParentID pointing to parent-lib
	relData := javaCataloger.NewDependencyRelationshipDataWithParent(1, "compile", "org.dep:parent-lib:2.0")
	rel := depOfRel(child, root, relData) // currently points to root (wrong)

	s := newTestSBOM(
		[]pkg.Package{root, parent, child},
		[]artifact.Relationship{rel},
	)

	builder := sbomsync.NewBuilder(s)
	accessor := builder.(sbomsync.Accessor)

	ResolveHierarchicalDependencies(accessor, cataloging.RelationshipsConfig{
		JavaMavenDependencyTreeFile: "../../../syft/pkg/cataloger/java/testdata/maven-dependency-tree.txt",
	})

	require.Len(t, s.Relationships, 1)
	// Relationship should now point to parent, not root
	assert.Equal(t, parent.ID(), s.Relationships[0].To.ID())

	data, ok := s.Relationships[0].Data.(javaCataloger.DependencyRelationshipData)
	require.True(t, ok)
	assert.Empty(t, data.IntendedParentID) // should be cleared
}

func TestResolveIntendedParent_ParentNotFound_FallsBackToAncestor(t *testing.T) {
	root := javaPkg("com.example", "my-app", "1.0.0")
	// spring-jcl's parent in the tree is spring-core, but spring-core is missing from SBOM
	springJcl := javaPkg("org.springframework", "spring-jcl", "6.2.15")

	relData := javaCataloger.NewDependencyRelationshipDataWithParent(1, "compile", "org.springframework:spring-core:6.2.15")
	rel := depOfRel(springJcl, root, relData)

	s := newTestSBOM(
		[]pkg.Package{root, springJcl}, // spring-core intentionally missing
		[]artifact.Relationship{rel},
	)

	builder := sbomsync.NewBuilder(s)
	accessor := builder.(sbomsync.Accessor)

	ResolveHierarchicalDependencies(accessor, cataloging.RelationshipsConfig{
		JavaMavenDependencyTreeFile: "../../../syft/pkg/cataloger/java/testdata/maven-dependency-tree.txt",
	})

	require.Len(t, s.Relationships, 1)
	// spring-core is missing; walk up tree → root (my-app) is the ancestor
	assert.Equal(t, root.ID(), s.Relationships[0].To.ID())

	data, ok := s.Relationships[0].Data.(javaCataloger.DependencyRelationshipData)
	require.True(t, ok)
	assert.Empty(t, data.IntendedParentID)
}

func TestEnrichFromGraph_Case2(t *testing.T) {
	// Case 2: No IntendedParentID, depGraph exists — enrich depth/scope
	root := javaPkg("com.example", "my-app", "1.0.0")
	jacksonDatabind := javaPkg("com.fasterxml.jackson.core", "jackson-databind", "2.19.4")

	// Flat relationship with no metadata
	rel := depOfRel(jacksonDatabind, root, nil)

	s := newTestSBOM(
		[]pkg.Package{root, jacksonDatabind},
		[]artifact.Relationship{rel},
	)

	builder := sbomsync.NewBuilder(s)
	accessor := builder.(sbomsync.Accessor)

	ResolveHierarchicalDependencies(accessor, cataloging.RelationshipsConfig{
		JavaMavenDependencyTreeFile: "../../../syft/pkg/cataloger/java/testdata/maven-dependency-tree.txt",
	})

	require.Len(t, s.Relationships, 1)

	data, ok := s.Relationships[0].Data.(javaCataloger.DependencyRelationshipData)
	require.True(t, ok)
	assert.Equal(t, 0, data.Depth) // direct dep in tree
	assert.True(t, data.IsDirectDependency)
	assert.Equal(t, "compile", data.Scope)
}

func TestEnrichFromGraph_TransitiveCorrection(t *testing.T) {
	// Verify that previously-flat deps get corrected to transitive
	root := javaPkg("com.example", "my-app", "1.0.0")
	// jackson-core is transitive (child of jackson-databind) in the fixture
	jacksonCore := javaPkg("com.fasterxml.jackson.core", "jackson-core", "2.19.4")

	rel := depOfRel(jacksonCore, root, nil)

	s := newTestSBOM(
		[]pkg.Package{root, jacksonCore},
		[]artifact.Relationship{rel},
	)

	builder := sbomsync.NewBuilder(s)
	accessor := builder.(sbomsync.Accessor)

	ResolveHierarchicalDependencies(accessor, cataloging.RelationshipsConfig{
		JavaMavenDependencyTreeFile: "../../../syft/pkg/cataloger/java/testdata/maven-dependency-tree.txt",
	})

	require.Len(t, s.Relationships, 1)

	data, ok := s.Relationships[0].Data.(javaCataloger.DependencyRelationshipData)
	require.True(t, ok)
	assert.Equal(t, 1, data.Depth) // transitive (depth=2 in graph → relDepth=1)
	assert.False(t, data.IsDirectDependency)
	assert.Equal(t, "compile", data.Scope)
}

func TestNonJavaRelationshipsSkipped(t *testing.T) {
	goPkg := pkg.Package{
		Name:     "some-go-pkg",
		Version:  "1.0",
		Language: pkg.Go,
		Type:     pkg.GoModulePkg,
	}
	goPkg.SetID()

	root := javaPkg("com.example", "my-app", "1.0.0")

	rel := depOfRel(goPkg, root, nil)

	s := newTestSBOM(
		[]pkg.Package{goPkg, root},
		[]artifact.Relationship{rel},
	)

	builder := sbomsync.NewBuilder(s)
	accessor := builder.(sbomsync.Accessor)

	ResolveHierarchicalDependencies(accessor, cataloging.RelationshipsConfig{
		JavaMavenDependencyTreeFile: "../../../syft/pkg/cataloger/java/testdata/maven-dependency-tree.txt",
	})

	require.Len(t, s.Relationships, 1)
	// Non-Java relationship should be untouched
	assert.Nil(t, s.Relationships[0].Data)
}

func TestNonDependencyOfRelationshipsSkipped(t *testing.T) {
	root := javaPkg("com.example", "root", "1.0")
	child := javaPkg("org.dep", "child", "2.0")

	rel := artifact.Relationship{
		From: child,
		To:   root,
		Type: artifact.ContainsRelationship,
	}

	s := newTestSBOM(
		[]pkg.Package{root, child},
		[]artifact.Relationship{rel},
	)

	builder := sbomsync.NewBuilder(s)
	accessor := builder.(sbomsync.Accessor)

	ResolveHierarchicalDependencies(accessor, cataloging.RelationshipsConfig{
		JavaMavenDependencyTreeFile: "../../../syft/pkg/cataloger/java/testdata/maven-dependency-tree.txt",
	})

	require.Len(t, s.Relationships, 1)
	assert.Equal(t, artifact.ContainsRelationship, s.Relationships[0].Type)
	assert.Nil(t, s.Relationships[0].Data)
}

func TestEmptySBOM(t *testing.T) {
	s := newTestSBOM(nil, nil)

	builder := sbomsync.NewBuilder(s)
	accessor := builder.(sbomsync.Accessor)

	// Should not panic
	ResolveHierarchicalDependencies(accessor, cataloging.RelationshipsConfig{
		JavaMavenDependencyTreeFile: "../../../syft/pkg/cataloger/java/testdata/maven-dependency-tree.txt",
	})

	assert.Empty(t, s.Relationships)
}

func TestFindPackageByMavenID_FlexibleMatch(t *testing.T) {
	p := javaPkg("com.example", "my-lib", "1.0")

	pkgIndex := map[string]*pkg.Package{
		"com.example:my-lib:1.0": &p,
		"com.example:my-lib":     &p,
		"my-lib":                 &p,
	}

	t.Run("exact match", func(t *testing.T) {
		found := findPackageByMavenID(pkgIndex, "com.example:my-lib:1.0")
		require.NotNil(t, found)
		assert.Equal(t, p.ID(), found.ID())
	})

	t.Run("groupId:artifactId match", func(t *testing.T) {
		found := findPackageByMavenID(pkgIndex, "com.example:my-lib:2.0")
		require.NotNil(t, found)
		assert.Equal(t, p.ID(), found.ID())
	})

	t.Run("artifactId-only match", func(t *testing.T) {
		found := findPackageByMavenID(pkgIndex, "org.other:my-lib:3.0")
		require.NotNil(t, found)
		assert.Equal(t, p.ID(), found.ID())
	})

	t.Run("not found", func(t *testing.T) {
		found := findPackageByMavenID(pkgIndex, "com.example:other-lib:1.0")
		assert.Nil(t, found)
	})
}

func TestFindNearestAncestorInSBOM(t *testing.T) {
	root := javaPkg("com.example", "root", "1.0")
	grandparent := javaPkg("org.dep", "grandparent", "2.0")

	pkgIndex := map[string]*pkg.Package{
		"com.example:root:1.0":    &root,
		"com.example:root":        &root,
		"root":                    &root,
		"org.dep:grandparent:2.0": &grandparent,
		"org.dep:grandparent":     &grandparent,
		"grandparent":             &grandparent,
	}

	t.Run("returns root when node is nil", func(t *testing.T) {
		ancestor := findNearestAncestorInSBOM(nil, nil, pkgIndex, &root)
		require.NotNil(t, ancestor)
		assert.Equal(t, root.ID(), ancestor.ID())
	})

	t.Run("returns root when entire chain missing", func(t *testing.T) {
		// Create a node whose parent chain has no matches in pkgIndex
		missingNode := &javaCataloger.DependencyNode{
			Depth: 3,
			Parent: &javaCataloger.DependencyNode{
				Depth: 2,
				Parent: &javaCataloger.DependencyNode{
					Depth:  1,
					Parent: nil, // chain ends without match
				},
			},
		}

		ancestor := findNearestAncestorInSBOM(nil, missingNode, pkgIndex, &root)
		require.NotNil(t, ancestor)
		assert.Equal(t, root.ID(), ancestor.ID())
	})
}

func TestExtractMavenID(t *testing.T) {
	tests := []struct {
		name     string
		pkg      *pkg.Package
		expected string
	}{
		{
			name:     "nil package",
			pkg:      nil,
			expected: "",
		},
		{
			name: "with pom properties",
			pkg: func() *pkg.Package {
				p := javaPkg("com.example", "my-lib", "1.0")
				return &p
			}(),
			expected: "com.example:my-lib:1.0",
		},
		{
			name: "missing groupId",
			pkg: &pkg.Package{
				Name:     "orphan",
				Version:  "1.0",
				Language: pkg.Java,
				Metadata: pkg.JavaArchive{
					PomProperties: &pkg.JavaPomProperties{
						ArtifactID: "orphan",
						Version:    "1.0",
					},
				},
			},
			expected: "",
		},
		{
			name: "groupId from pom project fallback",
			pkg: &pkg.Package{
				Name:     "my-lib",
				Version:  "1.0",
				Language: pkg.Java,
				Metadata: pkg.JavaArchive{
					PomProject: &pkg.JavaPomProject{
						GroupID: "com.fallback",
					},
					PomProperties: &pkg.JavaPomProperties{
						ArtifactID: "my-lib",
						Version:    "1.0",
					},
				},
			},
			expected: "com.fallback:my-lib:1.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractMavenID(tt.pkg)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractGroupArtifact(t *testing.T) {
	assert.Equal(t, "com.example:my-lib", extractGroupArtifact("com.example:my-lib:1.0"))
	assert.Equal(t, "", extractGroupArtifact("invalid"))
}

func TestExtractArtifactID(t *testing.T) {
	assert.Equal(t, "my-lib", extractArtifactID("com.example:my-lib:1.0"))
	assert.Equal(t, "", extractArtifactID("invalid"))
}

func TestParseMavenID(t *testing.T) {
	id := parseMavenID("com.example:my-lib:1.0")
	assert.Equal(t, "com.example", id.GroupID)
	assert.Equal(t, "my-lib", id.ArtifactID)
	assert.Equal(t, "1.0", id.Version)

	empty := parseMavenID("invalid")
	assert.False(t, empty.Valid())
}

// TestEndToEnd_FullPipeline exercises the complete post-processing pipeline with the
// Maven tree fixture. It creates a realistic SBOM with packages at various depths and
// flat relationships (all pointing to root), then verifies the post-processor correctly
// enriches depth/scope and re-parents transitive dependencies.
func TestEndToEnd_FullPipeline(t *testing.T) {
	treeFile := "../../../syft/pkg/cataloger/java/testdata/maven-dependency-tree.txt"

	// Create packages matching the fixture tree:
	// com.example:my-app:1.0.0 (root)
	//   +- jackson-databind (depth=1, direct)
	//   |  +- jackson-core (depth=2, transitive)
	//   |  \- jackson-annotations (depth=2, transitive)
	//   +- spring-core (depth=1, direct)
	//   |  \- spring-jcl (depth=2, transitive)
	//   +- micrometer-core (depth=1, direct)
	//   |  +- HdrHistogram (depth=2, transitive, runtime)
	//   \- junit-jupiter (depth=1, test)
	//      +- junit-jupiter-api (depth=2, test)
	//      \- junit-jupiter-engine (depth=2, test)
	//         \- junit-platform-engine (depth=3, test)
	root := javaPkg("com.example", "my-app", "1.0.0")
	jacksonDatabind := javaPkg("com.fasterxml.jackson.core", "jackson-databind", "2.19.4")
	jacksonCore := javaPkg("com.fasterxml.jackson.core", "jackson-core", "2.19.4")
	jacksonAnnotations := javaPkg("com.fasterxml.jackson.core", "jackson-annotations", "2.19.4")
	springCore := javaPkg("org.springframework", "spring-core", "6.2.15")
	springJcl := javaPkg("org.springframework", "spring-jcl", "6.2.15")
	micrometerCore := javaPkg("io.micrometer", "micrometer-core", "1.15.7")
	hdrHistogram := javaPkg("org.hdrhistogram", "HdrHistogram", "2.2.2")
	junitJupiter := javaPkg("org.junit.jupiter", "junit-jupiter", "5.11.6")
	junitApi := javaPkg("org.junit.jupiter", "junit-jupiter-api", "5.11.6")
	junitEngine := javaPkg("org.junit.jupiter", "junit-jupiter-engine", "5.11.6")
	junitPlatform := javaPkg("org.junit.platform", "junit-platform-engine", "1.11.6")

	// Also add a package NOT in the tree (should be unchanged)
	extraPkg := javaPkg("com.custom", "shaded-extra", "1.0")

	allPkgs := []pkg.Package{
		root, jacksonDatabind, jacksonCore, jacksonAnnotations,
		springCore, springJcl, micrometerCore, hdrHistogram,
		junitJupiter, junitApi, junitEngine, junitPlatform, extraPkg,
	}

	// All relationships start flat: everything points to root (simulating pre-fix behavior)
	var flatRels []artifact.Relationship
	for _, p := range allPkgs[1:] { // skip root
		flatRels = append(flatRels, depOfRel(p, root, nil))
	}

	s := newTestSBOM(allPkgs, flatRels)
	builder := sbomsync.NewBuilder(s)
	accessor := builder.(sbomsync.Accessor)

	ResolveHierarchicalDependencies(accessor, cataloging.RelationshipsConfig{
		JavaMavenDependencyTreeFile: treeFile,
	})

	require.Len(t, s.Relationships, len(allPkgs)-1) // 12 relationships (one per non-root package)

	// Build a lookup: from-package-name → relationship data
	type relInfo struct {
		depth    int
		isDirect bool
		scope    string
	}
	relMap := make(map[string]relInfo)
	for _, rel := range s.Relationships {
		fromPkg := rel.From.(pkg.Package)
		data, ok := rel.Data.(javaCataloger.DependencyRelationshipData)
		if ok {
			relMap[fromPkg.Name] = relInfo{depth: data.Depth, isDirect: data.IsDirectDependency, scope: data.Scope}
		} else {
			relMap[fromPkg.Name] = relInfo{depth: -1} // sentinel for unenriched
		}
	}

	// Direct dependencies (depth=0)
	for _, name := range []string{"jackson-databind", "spring-core", "micrometer-core", "junit-jupiter"} {
		info, ok := relMap[name]
		require.True(t, ok, "expected relationship for %s", name)
		assert.Equal(t, 0, info.depth, "%s should be depth=0", name)
		assert.True(t, info.isDirect, "%s should be direct", name)
	}

	// Compile scope
	assert.Equal(t, "compile", relMap["jackson-databind"].scope)
	assert.Equal(t, "compile", relMap["spring-core"].scope)
	assert.Equal(t, "compile", relMap["micrometer-core"].scope)

	// Test scope
	assert.Equal(t, "test", relMap["junit-jupiter"].scope)

	// Transitive dependencies (depth=1)
	for _, name := range []string{"jackson-core", "jackson-annotations", "spring-jcl", "HdrHistogram", "junit-jupiter-api", "junit-jupiter-engine"} {
		info, ok := relMap[name]
		require.True(t, ok, "expected relationship for %s", name)
		assert.Equal(t, 1, info.depth, "%s should be depth=1", name)
		assert.False(t, info.isDirect, "%s should be transitive", name)
	}

	// Runtime scope for HdrHistogram
	assert.Equal(t, "runtime", relMap["HdrHistogram"].scope)

	// Depth=2 transitive (junit-platform-engine is 3 levels deep in tree → relDepth=2)
	info, ok := relMap["junit-platform-engine"]
	require.True(t, ok)
	assert.Equal(t, 2, info.depth)
	assert.False(t, info.isDirect)
	assert.Equal(t, "test", info.scope)

	// Package not in tree should be unchanged (no enrichment data)
	assert.Equal(t, -1, relMap["shaded-extra"].depth, "package not in tree should have no enrichment")
}

func BenchmarkPostProcessingPipeline(b *testing.B) {
	treeFile := "../../../syft/pkg/cataloger/java/testdata/maven-dependency-tree.txt"

	// Build a realistic SBOM with 300 packages
	allPkgs := []pkg.Package{javaPkg("com.example", "root", "1.0.0")}
	for i := 0; i < 50; i++ {
		allPkgs = append(allPkgs, javaPkg("org.dep", fmt.Sprintf("direct-%d", i), fmt.Sprintf("%d.0", i)))
		for j := 0; j < 5; j++ {
			allPkgs = append(allPkgs, javaPkg("org.dep", fmt.Sprintf("trans-%d-%d", i, j), fmt.Sprintf("%d.%d", i, j)))
		}
	}

	var flatRels []artifact.Relationship
	root := allPkgs[0]
	for _, p := range allPkgs[1:] {
		flatRels = append(flatRels, depOfRel(p, root, nil))
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		s := newTestSBOM(allPkgs, flatRels)
		builder := sbomsync.NewBuilder(s)
		accessor := builder.(sbomsync.Accessor)
		ResolveHierarchicalDependencies(accessor, cataloging.RelationshipsConfig{
			JavaMavenDependencyTreeFile: treeFile,
		})
	}
}

func BenchmarkPostProcessingPipeline_Disabled(b *testing.B) {
	// Verify minimal overhead when feature is disabled
	allPkgs := []pkg.Package{javaPkg("com.example", "root", "1.0.0")}
	for i := 0; i < 300; i++ {
		allPkgs = append(allPkgs, javaPkg("org.dep", fmt.Sprintf("lib-%d", i), fmt.Sprintf("%d.0", i)))
	}

	var flatRels []artifact.Relationship
	root := allPkgs[0]
	for _, p := range allPkgs[1:] {
		flatRels = append(flatRels, depOfRel(p, root, nil))
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		s := newTestSBOM(allPkgs, flatRels)
		builder := sbomsync.NewBuilder(s)
		accessor := builder.(sbomsync.Accessor)
		ResolveHierarchicalDependencies(accessor, cataloging.RelationshipsConfig{})
	}
}
