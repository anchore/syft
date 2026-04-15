package java

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/java/internal/maven"
)

func TestExtractMavenIDFromPackage(t *testing.T) {
	tests := []struct {
		name     string
		pkg      *pkg.Package
		expected maven.ID
	}{
		{
			name:     "nil package",
			pkg:      nil,
			expected: maven.ID{},
		},
		{
			name: "no java metadata",
			pkg: &pkg.Package{
				Name:    "some-pkg",
				Version: "1.0",
			},
			expected: maven.ID{},
		},
		{
			name: "with pom properties",
			pkg: &pkg.Package{
				Name:    "some-pkg",
				Version: "1.0",
				Metadata: pkg.JavaArchive{
					PomProperties: &pkg.JavaPomProperties{
						GroupID:    "com.example",
						ArtifactID: "some-pkg",
						Version:    "1.0",
					},
				},
			},
			expected: maven.NewID("com.example", "some-pkg", "1.0"),
		},
		{
			name: "pom properties version overrides package version",
			pkg: &pkg.Package{
				Name:    "my-lib",
				Version: "2.0",
				Metadata: pkg.JavaArchive{
					PomProperties: &pkg.JavaPomProperties{
						GroupID:    "org.test",
						ArtifactID: "my-lib",
						Version:    "2.1",
					},
				},
			},
			expected: maven.NewID("org.test", "my-lib", "2.1"),
		},
		{
			name: "pom properties without artifactId uses package name",
			pkg: &pkg.Package{
				Name:    "fallback-name",
				Version: "3.0",
				Metadata: pkg.JavaArchive{
					PomProperties: &pkg.JavaPomProperties{
						GroupID: "org.fallback",
						Version: "3.0",
					},
				},
			},
			expected: maven.NewID("org.fallback", "fallback-name", "3.0"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractMavenIDFromPackage(tt.pkg)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCreateMainPkgRelationship_NoGraph(t *testing.T) {
	parser := &archiveParser{
		depth: 1,
	}

	mainPkg := &pkg.Package{Name: "child", Version: "1.0"}
	parentPkg := &pkg.Package{Name: "parent", Version: "2.0"}

	rel := parser.createMainPkgRelationship(mainPkg, parentPkg)

	assert.Equal(t, artifact.DependencyOfRelationship, rel.Type)
	assert.Nil(t, rel.Data)
}

func TestCreateMainPkgRelationship_DepthZero(t *testing.T) {
	graph := NewDependencyGraph()
	graph.SetRoot(maven.NewID("com.example", "root", "1.0"))
	graph.AddNode(maven.NewID("com.example", "child", "2.0"), "compile", graph.Root)

	parser := &archiveParser{
		depth:           0,
		dependencyGraph: graph,
	}

	mainPkg := &pkg.Package{
		Name:    "child",
		Version: "2.0",
		Metadata: pkg.JavaArchive{
			PomProperties: &pkg.JavaPomProperties{
				GroupID:    "com.example",
				ArtifactID: "child",
				Version:    "2.0",
			},
		},
	}
	parentPkg := &pkg.Package{Name: "root", Version: "1.0"}

	rel := parser.createMainPkgRelationship(mainPkg, parentPkg)

	// At depth=0, graph enrichment should NOT be applied (root level relationships don't need it)
	assert.Nil(t, rel.Data)
}

func TestCreateMainPkgRelationship_WithGraph(t *testing.T) {
	graph := NewDependencyGraph()
	root := graph.SetRoot(maven.NewID("com.example", "root", "1.0"))
	directNode := graph.AddNode(maven.NewID("com.example", "direct", "2.0"), "compile", root)
	graph.AddNode(maven.NewID("com.example", "transitive", "3.0"), "runtime", directNode)

	parser := &archiveParser{
		depth:           1,
		dependencyGraph: graph,
	}

	// Test direct dependency (depth=1 in graph → relDepth=0)
	t.Run("direct dependency", func(t *testing.T) {
		mainPkg := &pkg.Package{
			Name:    "direct",
			Version: "2.0",
			Metadata: pkg.JavaArchive{
				PomProperties: &pkg.JavaPomProperties{
					GroupID:    "com.example",
					ArtifactID: "direct",
					Version:    "2.0",
				},
			},
		}
		parentPkg := &pkg.Package{Name: "root", Version: "1.0"}

		rel := parser.createMainPkgRelationship(mainPkg, parentPkg)

		require.NotNil(t, rel.Data)
		data := rel.Data.(DependencyRelationshipData)
		assert.Equal(t, 0, data.Depth)
		assert.True(t, data.IsDirectDependency)
		assert.Equal(t, "compile", data.Scope)
		assert.Equal(t, "com.example:root:1.0", data.IntendedParentID)
	})

	// Test transitive dependency (depth=2 in graph → relDepth=1)
	t.Run("transitive dependency", func(t *testing.T) {
		mainPkg := &pkg.Package{
			Name:    "transitive",
			Version: "3.0",
			Metadata: pkg.JavaArchive{
				PomProperties: &pkg.JavaPomProperties{
					GroupID:    "com.example",
					ArtifactID: "transitive",
					Version:    "3.0",
				},
			},
		}
		parentPkg := &pkg.Package{Name: "root", Version: "1.0"}

		rel := parser.createMainPkgRelationship(mainPkg, parentPkg)

		require.NotNil(t, rel.Data)
		data := rel.Data.(DependencyRelationshipData)
		assert.Equal(t, 1, data.Depth)
		assert.False(t, data.IsDirectDependency)
		assert.Equal(t, "runtime", data.Scope)
		assert.Equal(t, "com.example:direct:2.0", data.IntendedParentID)
	})

	// Test package not found in graph — no enrichment
	t.Run("not found in graph", func(t *testing.T) {
		mainPkg := &pkg.Package{
			Name:    "unknown",
			Version: "9.9",
			Metadata: pkg.JavaArchive{
				PomProperties: &pkg.JavaPomProperties{
					GroupID:    "com.other",
					ArtifactID: "unknown",
					Version:    "9.9",
				},
			},
		}
		parentPkg := &pkg.Package{Name: "root", Version: "1.0"}

		rel := parser.createMainPkgRelationship(mainPkg, parentPkg)
		assert.Nil(t, rel.Data)
	})
}

func TestCreateAuxPkgRelationship_NoGraph(t *testing.T) {
	parser := &archiveParser{}

	auxPkg := &pkg.Package{Name: "aux", Version: "1.0"}
	mainPkg := &pkg.Package{Name: "main", Version: "2.0"}

	rel := parser.createAuxPkgRelationship(auxPkg, mainPkg)

	assert.Equal(t, artifact.DependencyOfRelationship, rel.Type)
	assert.Nil(t, rel.Data)
}

func TestCreateAuxPkgRelationship_WithGraph(t *testing.T) {
	graph := NewDependencyGraph()
	root := graph.SetRoot(maven.NewID("com.example", "root", "1.0"))
	directNode := graph.AddNode(maven.NewID("org.dep", "lib-a", "2.0"), "compile", root)
	graph.AddNode(maven.NewID("org.dep", "lib-b", "3.0"), "runtime", directNode)

	parser := &archiveParser{
		dependencyGraph: graph,
	}

	t.Run("aux package found in graph as direct", func(t *testing.T) {
		auxPkg := &pkg.Package{
			Name:    "lib-a",
			Version: "2.0",
			Metadata: pkg.JavaArchive{
				PomProperties: &pkg.JavaPomProperties{
					GroupID:    "org.dep",
					ArtifactID: "lib-a",
					Version:    "2.0",
				},
			},
		}
		mainPkg := &pkg.Package{Name: "root", Version: "1.0"}

		rel := parser.createAuxPkgRelationship(auxPkg, mainPkg)

		require.NotNil(t, rel.Data)
		data := rel.Data.(DependencyRelationshipData)
		assert.Equal(t, 0, data.Depth)
		assert.True(t, data.IsDirectDependency)
		assert.Equal(t, "compile", data.Scope)
		assert.Equal(t, "com.example:root:1.0", data.IntendedParentID)
	})

	t.Run("aux package found in graph as transitive", func(t *testing.T) {
		auxPkg := &pkg.Package{
			Name:    "lib-b",
			Version: "3.0",
			Metadata: pkg.JavaArchive{
				PomProperties: &pkg.JavaPomProperties{
					GroupID:    "org.dep",
					ArtifactID: "lib-b",
					Version:    "3.0",
				},
			},
		}
		mainPkg := &pkg.Package{Name: "root", Version: "1.0"}

		rel := parser.createAuxPkgRelationship(auxPkg, mainPkg)

		require.NotNil(t, rel.Data)
		data := rel.Data.(DependencyRelationshipData)
		assert.Equal(t, 1, data.Depth)
		assert.False(t, data.IsDirectDependency)
		assert.Equal(t, "runtime", data.Scope)
		assert.Equal(t, "org.dep:lib-a:2.0", data.IntendedParentID)
	})

	t.Run("aux package not in graph", func(t *testing.T) {
		auxPkg := &pkg.Package{
			Name:    "not-in-graph",
			Version: "1.0",
			Metadata: pkg.JavaArchive{
				PomProperties: &pkg.JavaPomProperties{
					GroupID:    "com.unknown",
					ArtifactID: "not-in-graph",
					Version:    "1.0",
				},
			},
		}
		mainPkg := &pkg.Package{Name: "root", Version: "1.0"}

		rel := parser.createAuxPkgRelationship(auxPkg, mainPkg)
		assert.Nil(t, rel.Data)
	})
}

func TestCreateMainPkgRelationship_FlexibleMatch(t *testing.T) {
	// Test that version mismatches are handled via flexible matching (Tier 2: groupId:artifactId)
	graph := NewDependencyGraph()
	root := graph.SetRoot(maven.NewID("com.example", "root", "1.0"))
	graph.AddNode(maven.NewID("org.dep", "lib-a", "2.0"), "compile", root)

	parser := &archiveParser{
		depth:           1,
		dependencyGraph: graph,
	}

	// Package has version 2.1 but graph has 2.0 — should match via groupId:artifactId
	mainPkg := &pkg.Package{
		Name:    "lib-a",
		Version: "2.1",
		Metadata: pkg.JavaArchive{
			PomProperties: &pkg.JavaPomProperties{
				GroupID:    "org.dep",
				ArtifactID: "lib-a",
				Version:    "2.1",
			},
		},
	}
	parentPkg := &pkg.Package{Name: "root", Version: "1.0"}

	rel := parser.createMainPkgRelationship(mainPkg, parentPkg)
	require.NotNil(t, rel.Data)
	data := rel.Data.(DependencyRelationshipData)
	assert.Equal(t, 0, data.Depth)
	assert.Equal(t, "compile", data.Scope)
}

func TestBuildGraphFromMavenTreeFile(t *testing.T) {
	parser := &archiveParser{
		cfg: ArchiveCatalogerConfig{
			MavenDependencyTreeFile: "testdata/maven-dependency-tree.txt",
		},
	}

	graph, err := parser.buildGraphFromMavenTreeFile()
	require.NoError(t, err)
	require.NotNil(t, graph)
	assert.Equal(t, 16, graph.Size())
	assert.Equal(t, "my-app", graph.Root.ID.ArtifactID)
}

func TestBuildGraphFromMavenTreeFile_NotFound(t *testing.T) {
	parser := &archiveParser{
		cfg: ArchiveCatalogerConfig{
			MavenDependencyTreeFile: "testdata/nonexistent-file.txt",
		},
	}

	graph, err := parser.buildGraphFromMavenTreeFile()
	assert.Error(t, err)
	assert.Nil(t, graph)
}

func TestBuildDependencyGraph_PriorityChain(t *testing.T) {
	t.Run("maven tree file takes priority", func(t *testing.T) {
		parser := &archiveParser{
			cfg: ArchiveCatalogerConfig{
				MavenDependencyTreeFile:    "testdata/maven-dependency-tree.txt",
				UseEmbeddedPOMDependencies: true,
			},
		}

		mainPkg := &pkg.Package{
			Name:    "my-app",
			Version: "1.0.0",
			Metadata: pkg.JavaArchive{
				PomProperties: &pkg.JavaPomProperties{
					GroupID:    "com.example",
					ArtifactID: "my-app",
					Version:    "1.0.0",
				},
			},
		}

		parser.buildDependencyGraph(nil, mainPkg)

		require.NotNil(t, parser.dependencyGraph)
		// The fixture has 16 nodes, so if the tree file was used, we get 16
		assert.Equal(t, 16, parser.dependencyGraph.Size())
	})

	t.Run("no graph when both features disabled", func(t *testing.T) {
		parser := &archiveParser{
			cfg: ArchiveCatalogerConfig{},
		}

		mainPkg := &pkg.Package{
			Name:    "my-app",
			Version: "1.0.0",
			Metadata: pkg.JavaArchive{},
		}

		parser.buildDependencyGraph(nil, mainPkg)
		assert.Nil(t, parser.dependencyGraph)
	})

	t.Run("graceful degradation on bad tree file with embedded POMs disabled", func(t *testing.T) {
		parser := &archiveParser{
			cfg: ArchiveCatalogerConfig{
				MavenDependencyTreeFile:    "testdata/nonexistent-file.txt",
				UseEmbeddedPOMDependencies: false,
			},
		}

		mainPkg := &pkg.Package{
			Name:    "my-app",
			Version: "1.0.0",
			Metadata: pkg.JavaArchive{},
		}

		parser.buildDependencyGraph(nil, mainPkg)
		// No graph — tree file failed and embedded POMs disabled
		assert.Nil(t, parser.dependencyGraph)
	})
}

func TestDepthConversion(t *testing.T) {
	// Verify the depth conversion: graph_depth - 1 = relationship_depth
	// Graph: 0=root, 1=direct, 2=transitive
	// Relationship: 0=direct, 1=first-level transitive

	graph := NewDependencyGraph()
	root := graph.SetRoot(maven.NewID("com.example", "root", "1.0"))
	direct := graph.AddNode(maven.NewID("com.example", "direct", "2.0"), "compile", root)
	graph.AddNode(maven.NewID("com.example", "transitive", "3.0"), "runtime", direct)

	// Root: graph depth=0, should never create a relationship (it IS the root)
	assert.Equal(t, 0, root.Depth)

	// Direct: graph depth=1, relationship depth should be 0
	directNode := graph.FindNode(maven.NewID("com.example", "direct", "2.0"))
	require.NotNil(t, directNode)
	relDepth := directNode.Depth - 1
	assert.Equal(t, 0, relDepth)

	// Transitive: graph depth=2, relationship depth should be 1
	transitiveNode := graph.FindNode(maven.NewID("com.example", "transitive", "3.0"))
	require.NotNil(t, transitiveNode)
	relDepth = transitiveNode.Depth - 1
	assert.Equal(t, 1, relDepth)
}

func TestBuildGraphFromMavenTreeFile_Integration(t *testing.T) {
	// Integration test: parse the fixture and verify graph structure matches expectations
	input := `com.example:root:jar:1.0
+- org.dep:direct-a:jar:2.0:compile
|  \- org.dep:transitive-b:jar:3.0:runtime
\- org.dep:direct-c:jar:4.0:test
`

	tree, err := ParseMavenDependencyTree(strings.NewReader(input))
	require.NoError(t, err)

	graph := tree.ToInternalGraph()
	require.NotNil(t, graph)

	// Verify the graph can be used for relationship creation
	parser := &archiveParser{
		depth:           1,
		dependencyGraph: graph,
	}

	// Package "direct-a" should be found at depth 1
	directPkg := &pkg.Package{
		Name:    "direct-a",
		Version: "2.0",
		Metadata: pkg.JavaArchive{
			PomProperties: &pkg.JavaPomProperties{
				GroupID:    "org.dep",
				ArtifactID: "direct-a",
				Version:    "2.0",
			},
		},
	}
	parentPkg := &pkg.Package{Name: "root", Version: "1.0"}
	rel := parser.createMainPkgRelationship(directPkg, parentPkg)

	require.NotNil(t, rel.Data)
	data := rel.Data.(DependencyRelationshipData)
	assert.Equal(t, 0, data.Depth)
	assert.True(t, data.IsDirectDependency)
	assert.Equal(t, "compile", data.Scope)
	assert.Equal(t, "com.example:root:1.0", data.IntendedParentID)

	// Package "transitive-b" should be found at depth 2, parent = direct-a
	transPkg := &pkg.Package{
		Name:    "transitive-b",
		Version: "3.0",
		Metadata: pkg.JavaArchive{
			PomProperties: &pkg.JavaPomProperties{
				GroupID:    "org.dep",
				ArtifactID: "transitive-b",
				Version:    "3.0",
			},
		},
	}
	rel = parser.createMainPkgRelationship(transPkg, parentPkg)

	require.NotNil(t, rel.Data)
	data = rel.Data.(DependencyRelationshipData)
	assert.Equal(t, 1, data.Depth)
	assert.False(t, data.IsDirectDependency)
	assert.Equal(t, "runtime", data.Scope)
	assert.Equal(t, "org.dep:direct-a:2.0", data.IntendedParentID)
}
