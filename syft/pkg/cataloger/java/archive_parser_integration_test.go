package java

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/java/internal/maven"
)

func TestBuildDependencyGraphFromEmbeddedPOMs_Integration(t *testing.T) {
	// Simulate a scenario where we have a root POM with two direct dependencies,
	// one of which has a transitive dependency
	rootID := maven.NewID("com.example", "root-app", "1.0.0")
	depAID := maven.NewID("com.example", "lib-a", "2.0.0")
	depBID := maven.NewID("org.other", "lib-b", "3.0.0")
	transitiveID := maven.NewID("org.transitive", "lib-c", "4.0.0")

	compileScope := "compile"
	runtimeScope := "runtime"

	rootPom := &maven.Project{
		Dependencies: &[]maven.Dependency{
			{GroupID: &depAID.GroupID, ArtifactID: &depAID.ArtifactID, Version: &depAID.Version, Scope: &compileScope},
			{GroupID: &depBID.GroupID, ArtifactID: &depBID.ArtifactID, Version: &depBID.Version, Scope: &runtimeScope},
		},
	}
	depAPom := &maven.Project{
		Dependencies: &[]maven.Dependency{
			{GroupID: &transitiveID.GroupID, ArtifactID: &transitiveID.ArtifactID, Version: &transitiveID.Version, Scope: &compileScope},
		},
	}

	poms := map[maven.ID]*maven.Project{
		rootID: rootPom,
		depAID: depAPom,
	}

	resolver := maven.NewResolver(nil, maven.DefaultConfig())

	graph := newDependencyGraph()
	graph.buildFromPOMs(context.Background(), poms, resolver, rootID, true, 10)

	// Verify graph structure
	require.Equal(t, 4, graph.size())

	nodeA := graph.findNode(depAID)
	require.NotNil(t, nodeA)
	assert.Equal(t, "compile", nodeA.Scope)
	assert.Equal(t, 1, nodeA.depth())
	assert.Equal(t, graph.Root, nodeA.Parent)

	nodeB := graph.findNode(depBID)
	require.NotNil(t, nodeB)
	assert.Equal(t, "runtime", nodeB.Scope)
	assert.Equal(t, 1, nodeB.depth())
	assert.Equal(t, graph.Root, nodeB.Parent)

	nodeC := graph.findNode(transitiveID)
	require.NotNil(t, nodeC)
	assert.Equal(t, "compile", nodeC.Scope)
	assert.Equal(t, 2, nodeC.depth())
	assert.Equal(t, nodeA, nodeC.Parent)
}

func TestCreateAuxPkgRelationship_WithGraph(t *testing.T) {
	// Setup: graph with root -> depA -> depB
	rootID := maven.NewID("com.example", "root", "1.0")
	depAID := maven.NewID("com.example", "dep-a", "2.0")
	depBID := maven.NewID("com.example", "dep-b", "3.0")

	graph := newDependencyGraph()
	root := graph.setRoot(rootID)
	nodeA := graph.addNode(depAID, "compile", root)
	graph.addNode(depBID, "runtime", nodeA)

	rootPkg := &pkg.Package{
		Name:    "root",
		Version: "1.0",
		Type:    pkg.JavaPkg,
		Metadata: pkg.JavaArchive{
			PomProperties: &pkg.JavaPomProperties{
				GroupID:    "com.example",
				ArtifactID: "root",
				Version:    "1.0",
			},
		},
	}
	rootPkg.SetID()

	depAPkg := &pkg.Package{
		Name:    "dep-a",
		Version: "2.0",
		Type:    pkg.JavaPkg,
		Metadata: pkg.JavaArchive{
			PomProperties: &pkg.JavaPomProperties{
				GroupID:    "com.example",
				ArtifactID: "dep-a",
				Version:    "2.0",
			},
		},
	}
	depAPkg.SetID()

	depBPkg := &pkg.Package{
		Name:    "dep-b",
		Version: "3.0",
		Type:    pkg.JavaPkg,
		Metadata: pkg.JavaArchive{
			PomProperties: &pkg.JavaPomProperties{
				GroupID:    "com.example",
				ArtifactID: "dep-b",
				Version:    "3.0",
			},
		},
	}
	depBPkg.SetID()

	parser := &archiveParser{
		dependencyGraph: graph,
	}

	pkgIndex := map[maven.ID]*pkg.Package{
		rootID: rootPkg,
		depAID: depAPkg,
	}

	t.Run("direct dependency wired to root", func(t *testing.T) {
		rel := parser.createAuxPkgRelationship(depAPkg, rootPkg, pkgIndex)
		assert.Equal(t, artifact.DependencyOfRelationship, rel.Type)
		// depA's parent is root, which is in pkgIndex
		assert.Equal(t, rootPkg.ID(), rel.To.(pkg.Package).ID())

		data, ok := rel.Data.(dependencyRelationshipData)
		require.True(t, ok)
		assert.Equal(t, 0, data.Depth)
		assert.True(t, data.IsDirectDependency)
		assert.Equal(t, "compile", data.Scope)
		assert.Empty(t, data.IntendedParentID)
	})

	t.Run("transitive dependency wired to parent in index", func(t *testing.T) {
		rel := parser.createAuxPkgRelationship(depBPkg, rootPkg, pkgIndex)
		assert.Equal(t, artifact.DependencyOfRelationship, rel.Type)
		// depB's parent is depA, which IS in pkgIndex
		assert.Equal(t, depAPkg.ID(), rel.To.(pkg.Package).ID())

		data, ok := rel.Data.(dependencyRelationshipData)
		require.True(t, ok)
		assert.Equal(t, 1, data.Depth)
		assert.False(t, data.IsDirectDependency)
		assert.Equal(t, "runtime", data.Scope)
		assert.Empty(t, data.IntendedParentID)
	})

	t.Run("transitive dependency deferred when parent not in index", func(t *testing.T) {
		// Remove depA from index to simulate it being in a different archive
		sparseIndex := map[maven.ID]*pkg.Package{
			rootID: rootPkg,
		}

		rel := parser.createAuxPkgRelationship(depBPkg, rootPkg, sparseIndex)
		assert.Equal(t, artifact.DependencyOfRelationship, rel.Type)
		// falls back to rootPkg since depA isn't in the index
		assert.Equal(t, rootPkg.ID(), rel.To.(pkg.Package).ID())

		data, ok := rel.Data.(dependencyRelationshipData)
		require.True(t, ok)
		assert.Equal(t, 1, data.Depth)
		assert.Equal(t, "com.example:dep-a:2.0", data.IntendedParentID)
	})
}

func TestCreateAuxPkgRelationship_WithoutGraph(t *testing.T) {
	rootPkg := &pkg.Package{
		Name:    "root",
		Version: "1.0",
		Type:    pkg.JavaPkg,
		Metadata: pkg.JavaArchive{
			PomProperties: &pkg.JavaPomProperties{
				GroupID:    "com.example",
				ArtifactID: "root",
				Version:    "1.0",
			},
		},
	}
	rootPkg.SetID()

	auxPkg := &pkg.Package{
		Name:    "aux",
		Version: "2.0",
		Type:    pkg.JavaPkg,
		Metadata: pkg.JavaArchive{
			PomProperties: &pkg.JavaPomProperties{
				GroupID:    "com.example",
				ArtifactID: "aux",
				Version:    "2.0",
			},
		},
	}
	auxPkg.SetID()

	parser := &archiveParser{
		dependencyGraph: nil,
	}

	pkgIndex := map[maven.ID]*pkg.Package{}

	rel := parser.createAuxPkgRelationship(auxPkg, rootPkg, pkgIndex)
	assert.Equal(t, artifact.DependencyOfRelationship, rel.Type)
	assert.Equal(t, rootPkg.ID(), rel.To.(pkg.Package).ID())
	assert.Nil(t, rel.Data)
}

func TestExtractMavenIDFromPackage(t *testing.T) {
	tests := []struct {
		name     string
		pkg      *pkg.Package
		expected maven.ID
	}{
		{
			name: "from pom properties",
			pkg: &pkg.Package{
				Metadata: pkg.JavaArchive{
					PomProperties: &pkg.JavaPomProperties{
						GroupID:    "com.example",
						ArtifactID: "my-lib",
						Version:    "1.0",
					},
				},
			},
			expected: maven.NewID("com.example", "my-lib", "1.0"),
		},
		{
			name: "from pom project when no properties",
			pkg: &pkg.Package{
				Metadata: pkg.JavaArchive{
					PomProject: &pkg.JavaPomProject{
						GroupID:    "org.other",
						ArtifactID: "other-lib",
						Version:    "2.0",
					},
				},
			},
			expected: maven.NewID("org.other", "other-lib", "2.0"),
		},
		{
			name:     "nil package",
			pkg:      nil,
			expected: maven.ID{},
		},
		{
			name: "non-java metadata",
			pkg: &pkg.Package{
				Metadata: nil,
			},
			expected: maven.ID{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractMavenIDFromPackage(tt.pkg))
		})
	}
}

func TestCreateMainPkgRelationship_WithGraph(t *testing.T) {
	rootID := maven.NewID("com.example", "root", "1.0")
	nestedID := maven.NewID("com.example", "nested", "2.0")

	graph := newDependencyGraph()
	root := graph.setRoot(rootID)
	graph.addNode(nestedID, "compile", root)

	mainPkg := &pkg.Package{
		Name:    "nested",
		Version: "2.0",
		Type:    pkg.JavaPkg,
		Metadata: pkg.JavaArchive{
			PomProperties: &pkg.JavaPomProperties{
				GroupID:    "com.example",
				ArtifactID: "nested",
				Version:    "2.0",
			},
		},
	}
	mainPkg.SetID()

	parentPkg := &pkg.Package{
		Name:    "root",
		Version: "1.0",
		Type:    pkg.JavaPkg,
	}
	parentPkg.SetID()

	t.Run("enriched at depth > 0", func(t *testing.T) {
		parser := &archiveParser{
			dependencyGraph: graph,
			depth:           1,
		}
		rel := parser.createMainPkgRelationship(mainPkg, parentPkg)
		assert.Equal(t, artifact.DependencyOfRelationship, rel.Type)

		data, ok := rel.Data.(dependencyRelationshipData)
		require.True(t, ok)
		assert.Equal(t, 0, data.Depth)
		assert.Equal(t, "compile", data.Scope)
	})

	t.Run("not enriched at depth 0", func(t *testing.T) {
		parser := &archiveParser{
			dependencyGraph: graph,
			depth:           0,
		}
		rel := parser.createMainPkgRelationship(mainPkg, parentPkg)
		assert.Equal(t, artifact.DependencyOfRelationship, rel.Type)
		assert.Nil(t, rel.Data)
	})
}

func TestMavenID_Coordinate(t *testing.T) {
	id := maven.NewID("com.example", "my-lib", "1.0.0")
	assert.Equal(t, "com.example:my-lib:1.0.0", id.Coordinate())

	empty := maven.ID{}
	assert.Equal(t, "::", empty.Coordinate())
}

func TestCreateAuxPkgRelationship_VersionMismatchFallback(t *testing.T) {
	// Graph declares dep-a at version 2.0, but the actual embedded JAR has version 2.1
	// (e.g. dependency management resolved a different version). FindNodeByGA should still match.
	rootID := maven.NewID("com.example", "root", "1.0")
	depAGraphID := maven.NewID("com.example", "dep-a", "2.0")

	graph := newDependencyGraph()
	root := graph.setRoot(rootID)
	graph.addNode(depAGraphID, "compile", root)

	rootPkg := &pkg.Package{
		Name:    "root",
		Version: "1.0",
		Type:    pkg.JavaPkg,
		Metadata: pkg.JavaArchive{
			PomProperties: &pkg.JavaPomProperties{
				GroupID:    "com.example",
				ArtifactID: "root",
				Version:    "1.0",
			},
		},
	}
	rootPkg.SetID()

	// auxPkg has version 2.1 — different from graph's 2.0
	auxPkg := &pkg.Package{
		Name:    "dep-a",
		Version: "2.1",
		Type:    pkg.JavaPkg,
		Metadata: pkg.JavaArchive{
			PomProperties: &pkg.JavaPomProperties{
				GroupID:    "com.example",
				ArtifactID: "dep-a",
				Version:    "2.1",
			},
		},
	}
	auxPkg.SetID()

	parser := &archiveParser{
		dependencyGraph: graph,
	}

	pkgIndex := map[maven.ID]*pkg.Package{
		rootID: rootPkg,
	}

	rel := parser.createAuxPkgRelationship(auxPkg, rootPkg, pkgIndex)
	assert.Equal(t, artifact.DependencyOfRelationship, rel.Type)
	assert.Equal(t, rootPkg.ID(), rel.To.(pkg.Package).ID())

	data, ok := rel.Data.(dependencyRelationshipData)
	require.True(t, ok)
	assert.Equal(t, 0, data.Depth)
	assert.True(t, data.IsDirectDependency)
	assert.Equal(t, "compile", data.Scope)
}
