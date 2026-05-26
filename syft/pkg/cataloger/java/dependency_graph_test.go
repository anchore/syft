package java

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/pkg/cataloger/java/internal/maven"
)

func TestDependencyGraph_BasicConstruction(t *testing.T) {
	g := NewDependencyGraph()

	rootID := maven.NewID("com.example", "root", "1.0")
	depA := maven.NewID("com.example", "dep-a", "2.0")
	depB := maven.NewID("com.example", "dep-b", "3.0")

	root := g.SetRoot(rootID)
	require.NotNil(t, root)
	assert.Equal(t, rootID, root.ID)
	assert.Nil(t, root.Parent)
	assert.Equal(t, 0, root.Depth())

	nodeA := g.AddNode(depA, "compile", root)
	require.NotNil(t, nodeA)
	assert.Equal(t, depA, nodeA.ID)
	assert.Equal(t, "compile", nodeA.Scope)
	assert.Equal(t, root, nodeA.Parent)
	assert.Equal(t, 1, nodeA.Depth())

	nodeB := g.AddNode(depB, "runtime", root)
	require.NotNil(t, nodeB)
	assert.Equal(t, "runtime", nodeB.Scope)
	assert.Equal(t, root, nodeB.Parent)
	assert.Equal(t, 1, nodeB.Depth())

	assert.Equal(t, 3, g.Size())
	assert.Len(t, root.Children, 2)
}

func TestDependencyGraph_DepthComputation(t *testing.T) {
	g := NewDependencyGraph()

	rootID := maven.NewID("com.example", "root", "1.0")
	level1 := maven.NewID("com.example", "level1", "1.0")
	level2 := maven.NewID("com.example", "level2", "1.0")
	level3 := maven.NewID("com.example", "level3", "1.0")

	root := g.SetRoot(rootID)
	n1 := g.AddNode(level1, "", root)
	n2 := g.AddNode(level2, "", n1)
	n3 := g.AddNode(level3, "", n2)

	assert.Equal(t, 0, root.Depth())
	assert.Equal(t, 1, n1.Depth())
	assert.Equal(t, 2, n2.Depth())
	assert.Equal(t, 3, n3.Depth())
}

func TestDependencyGraph_FindNode(t *testing.T) {
	g := NewDependencyGraph()

	rootID := maven.NewID("com.example", "root", "1.0")
	depID := maven.NewID("com.example", "dep", "2.0")
	missingID := maven.NewID("com.example", "missing", "1.0")

	g.SetRoot(rootID)
	g.AddNode(depID, "compile", g.Root)

	assert.NotNil(t, g.FindNode(rootID))
	assert.NotNil(t, g.FindNode(depID))
	assert.Nil(t, g.FindNode(missingID))
}

func TestDependencyGraph_FindNode_ExactMatchOnly(t *testing.T) {
	g := NewDependencyGraph()

	rootID := maven.NewID("com.example", "root", "1.0")
	depID := maven.NewID("com.example", "dep", "2.0")

	g.SetRoot(rootID)
	g.AddNode(depID, "", g.Root)

	// different version should not match
	differentVersion := maven.NewID("com.example", "dep", "3.0")
	assert.Nil(t, g.FindNode(differentVersion))

	// different groupID should not match
	differentGroup := maven.NewID("org.other", "dep", "2.0")
	assert.Nil(t, g.FindNode(differentGroup))
}

func TestDependencyGraph_AddNode_DuplicatePrevented(t *testing.T) {
	g := NewDependencyGraph()

	rootID := maven.NewID("com.example", "root", "1.0")
	depID := maven.NewID("com.example", "dep", "1.0")

	root := g.SetRoot(rootID)
	first := g.AddNode(depID, "compile", root)
	second := g.AddNode(depID, "runtime", root)

	// should return existing node, not create duplicate
	assert.Same(t, first, second)
	assert.Equal(t, 2, g.Size())
	// scope from first insertion is preserved
	assert.Equal(t, "compile", first.Scope)
}

func TestDependencyGraph_BuildFromPOMs(t *testing.T) {
	ctx := context.Background()

	rootID := maven.NewID("com.example", "root", "1.0")
	depAID := maven.NewID("com.example", "dep-a", "2.0")
	depBID := maven.NewID("com.example", "dep-b", "3.0")

	scope := "compile"

	rootPom := &maven.Project{
		Dependencies: &[]maven.Dependency{
			{GroupID: &depAID.GroupID, ArtifactID: &depAID.ArtifactID, Version: &depAID.Version, Scope: &scope},
			{GroupID: &depBID.GroupID, ArtifactID: &depBID.ArtifactID, Version: &depBID.Version},
		},
	}

	poms := map[maven.ID]*maven.Project{
		rootID: rootPom,
	}

	resolver := maven.NewResolver(nil, maven.DefaultConfig())

	g := NewDependencyGraph()
	g.BuildFromPOMs(ctx, poms, resolver, rootID, false, 10)

	assert.Equal(t, 3, g.Size())
	assert.NotNil(t, g.FindNode(rootID))
	assert.NotNil(t, g.FindNode(depAID))
	assert.NotNil(t, g.FindNode(depBID))

	nodeA := g.FindNode(depAID)
	assert.Equal(t, "compile", nodeA.Scope)
	assert.Equal(t, g.Root, nodeA.Parent)
}

func TestDependencyGraph_BuildFromPOMs_Transitive(t *testing.T) {
	ctx := context.Background()

	rootID := maven.NewID("com.example", "root", "1.0")
	depAID := maven.NewID("com.example", "dep-a", "2.0")
	depBID := maven.NewID("com.example", "dep-b", "3.0")

	rootPom := &maven.Project{
		Dependencies: &[]maven.Dependency{
			{GroupID: &depAID.GroupID, ArtifactID: &depAID.ArtifactID, Version: &depAID.Version},
		},
	}
	depAPom := &maven.Project{
		Dependencies: &[]maven.Dependency{
			{GroupID: &depBID.GroupID, ArtifactID: &depBID.ArtifactID, Version: &depBID.Version},
		},
	}

	poms := map[maven.ID]*maven.Project{
		rootID: rootPom,
		depAID: depAPom,
	}

	resolver := maven.NewResolver(nil, maven.DefaultConfig())

	g := NewDependencyGraph()
	g.BuildFromPOMs(ctx, poms, resolver, rootID, true, 10)

	assert.Equal(t, 3, g.Size())

	nodeB := g.FindNode(depBID)
	require.NotNil(t, nodeB)
	assert.Equal(t, 2, nodeB.Depth())

	nodeA := g.FindNode(depAID)
	require.NotNil(t, nodeA)
	assert.Equal(t, nodeA, nodeB.Parent)
}

func TestDependencyGraph_BuildFromPOMs_CyclePrevention(t *testing.T) {
	ctx := context.Background()

	rootID := maven.NewID("com.example", "root", "1.0")
	depAID := maven.NewID("com.example", "dep-a", "2.0")

	// dep-a depends back on root (cycle)
	rootPom := &maven.Project{
		Dependencies: &[]maven.Dependency{
			{GroupID: &depAID.GroupID, ArtifactID: &depAID.ArtifactID, Version: &depAID.Version},
		},
	}
	depAPom := &maven.Project{
		Dependencies: &[]maven.Dependency{
			{GroupID: &rootID.GroupID, ArtifactID: &rootID.ArtifactID, Version: &rootID.Version},
		},
	}

	poms := map[maven.ID]*maven.Project{
		rootID: rootPom,
		depAID: depAPom,
	}

	resolver := maven.NewResolver(nil, maven.DefaultConfig())

	g := NewDependencyGraph()
	g.BuildFromPOMs(ctx, poms, resolver, rootID, true, 10)

	// should not loop infinitely — root + dep-a only
	assert.Equal(t, 2, g.Size())
}

func TestDependencyGraph_BuildFromPOMs_MaxDepth(t *testing.T) {
	ctx := context.Background()

	rootID := maven.NewID("com.example", "root", "1.0")
	depAID := maven.NewID("com.example", "dep-a", "2.0")
	depBID := maven.NewID("com.example", "dep-b", "3.0")
	depCID := maven.NewID("com.example", "dep-c", "4.0")

	rootPom := &maven.Project{
		Dependencies: &[]maven.Dependency{
			{GroupID: &depAID.GroupID, ArtifactID: &depAID.ArtifactID, Version: &depAID.Version},
		},
	}
	depAPom := &maven.Project{
		Dependencies: &[]maven.Dependency{
			{GroupID: &depBID.GroupID, ArtifactID: &depBID.ArtifactID, Version: &depBID.Version},
		},
	}
	depBPom := &maven.Project{
		Dependencies: &[]maven.Dependency{
			{GroupID: &depCID.GroupID, ArtifactID: &depCID.ArtifactID, Version: &depCID.Version},
		},
	}

	poms := map[maven.ID]*maven.Project{
		rootID: rootPom,
		depAID: depAPom,
		depBID: depBPom,
	}

	resolver := maven.NewResolver(nil, maven.DefaultConfig())

	// maxDepth=2 should stop at dep-b (depth 2), not include dep-c
	g := NewDependencyGraph()
	g.BuildFromPOMs(ctx, poms, resolver, rootID, true, 2)

	assert.NotNil(t, g.FindNode(rootID))
	assert.NotNil(t, g.FindNode(depAID))
	assert.NotNil(t, g.FindNode(depBID))
	assert.Nil(t, g.FindNode(depCID))
}

func TestDependencyGraph_BuildFromPOMs_MissingRoot(t *testing.T) {
	ctx := context.Background()

	rootID := maven.NewID("com.example", "missing", "1.0")
	poms := map[maven.ID]*maven.Project{}

	resolver := maven.NewResolver(nil, maven.DefaultConfig())

	g := NewDependencyGraph()
	g.BuildFromPOMs(ctx, poms, resolver, rootID, true, 10)

	// graph should remain empty
	assert.Equal(t, 0, g.Size())
	assert.Nil(t, g.Root)
}

func TestDependencyGraph_Size(t *testing.T) {
	g := NewDependencyGraph()
	assert.Equal(t, 0, g.Size())

	root := g.SetRoot(maven.NewID("com.example", "root", "1.0"))
	assert.Equal(t, 1, g.Size())

	g.AddNode(maven.NewID("com.example", "a", "1.0"), "", root)
	assert.Equal(t, 2, g.Size())

	g.AddNode(maven.NewID("com.example", "b", "1.0"), "", root)
	assert.Equal(t, 3, g.Size())
}

func TestDependencyGraph_FindNodeByGA(t *testing.T) {
	g := NewDependencyGraph()

	rootID := maven.NewID("com.example", "root", "1.0")
	depID := maven.NewID("com.example", "dep", "2.0")

	root := g.SetRoot(rootID)
	g.AddNode(depID, "compile", root)

	t.Run("matches regardless of version", func(t *testing.T) {
		node := g.FindNodeByGA("com.example", "dep")
		require.NotNil(t, node)
		assert.Equal(t, depID, node.ID)
	})

	t.Run("different version still matches", func(t *testing.T) {
		node := g.FindNodeByGA("com.example", "dep")
		require.NotNil(t, node)
		assert.Equal(t, "2.0", node.ID.Version)
	})

	t.Run("wrong groupID does not match", func(t *testing.T) {
		assert.Nil(t, g.FindNodeByGA("org.other", "dep"))
	})

	t.Run("wrong artifactID does not match", func(t *testing.T) {
		assert.Nil(t, g.FindNodeByGA("com.example", "missing"))
	})
}
