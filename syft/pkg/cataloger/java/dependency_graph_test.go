package java

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/pkg/cataloger/java/internal/maven"
)

func TestDependencyGraph_SetRoot(t *testing.T) {
	g := NewDependencyGraph()
	root := g.SetRoot(maven.NewID("com.example", "root", "1.0"))

	assert.NotNil(t, root)
	assert.Equal(t, 0, root.Depth)
	assert.Nil(t, root.Parent)
	assert.Equal(t, g.Root, root)
	assert.Equal(t, 1, g.Size())
}

func TestDependencyGraph_AddNode_WithParent(t *testing.T) {
	g := NewDependencyGraph()
	root := g.SetRoot(maven.NewID("com.example", "root", "1.0"))

	child := g.AddNode(maven.NewID("org.dep", "child", "2.0"), "compile", root)
	assert.Equal(t, 1, child.Depth)
	assert.Equal(t, "compile", child.Scope)
	assert.Equal(t, root, child.Parent)
	assert.Contains(t, root.Children, child)
	assert.Equal(t, 2, g.Size())

	grandchild := g.AddNode(maven.NewID("org.dep", "grandchild", "3.0"), "runtime", child)
	assert.Equal(t, 2, grandchild.Depth)
	assert.Equal(t, child, grandchild.Parent)
}

func TestDependencyGraph_AddNode_DuplicateReturnsExisting(t *testing.T) {
	g := NewDependencyGraph()
	root := g.SetRoot(maven.NewID("com.example", "root", "1.0"))

	first := g.AddNode(maven.NewID("org.dep", "child", "2.0"), "compile", root)
	second := g.AddNode(maven.NewID("org.dep", "child", "2.0"), "runtime", root)

	assert.Same(t, first, second)
	assert.Equal(t, "compile", second.Scope) // keeps original scope
	assert.Equal(t, 2, g.Size())
}

func TestDependencyGraph_AddNode_NilParent(t *testing.T) {
	g := NewDependencyGraph()
	node := g.AddNode(maven.NewID("com.example", "orphan", "1.0"), "compile", nil)
	assert.Equal(t, 0, node.Depth)
	assert.Nil(t, node.Parent)
}

func TestDependencyGraph_FindNode_ExactMatch(t *testing.T) {
	g := NewDependencyGraph()
	root := g.SetRoot(maven.NewID("com.example", "root", "1.0"))
	g.AddNode(maven.NewID("org.dep", "child", "2.0"), "compile", root)

	found := g.FindNode(maven.NewID("org.dep", "child", "2.0"))
	assert.NotNil(t, found)
	assert.Equal(t, "child", found.ID.ArtifactID)

	notFound := g.FindNode(maven.NewID("org.dep", "child", "9.9"))
	assert.Nil(t, notFound)
}

func TestDependencyGraph_FindNodeFlexible_Tier1_Exact(t *testing.T) {
	g := NewDependencyGraph()
	root := g.SetRoot(maven.NewID("com.example", "root", "1.0"))
	g.AddNode(maven.NewID("org.dep", "child", "2.0"), "compile", root)

	found := g.FindNodeFlexible(maven.NewID("org.dep", "child", "2.0"))
	require.NotNil(t, found)
	assert.Equal(t, "child", found.ID.ArtifactID)
}

func TestDependencyGraph_FindNodeFlexible_Tier2_GroupArtifact(t *testing.T) {
	g := NewDependencyGraph()
	root := g.SetRoot(maven.NewID("com.example", "root", "1.0"))
	g.AddNode(maven.NewID("org.dep", "child", "2.0"), "compile", root)

	// version differs (BOM-managed)
	found := g.FindNodeFlexible(maven.NewID("org.dep", "child", "3.5"))
	require.NotNil(t, found)
	assert.Equal(t, "2.0", found.ID.Version) // returns the graph's version
}

func TestDependencyGraph_FindNodeFlexible_Tier3_ArtifactVersion(t *testing.T) {
	g := NewDependencyGraph()
	root := g.SetRoot(maven.NewID("com.example", "root", "1.0"))
	g.AddNode(maven.NewID("org.ow2.asm", "asm", "9.0"), "compile", root)

	// groupId changed (e.g., org.ow2.asm -> org.objectweb.asm)
	found := g.FindNodeFlexible(maven.NewID("org.objectweb.asm", "asm", "9.0"))
	require.NotNil(t, found)
	assert.Equal(t, "org.ow2.asm", found.ID.GroupID)
}

func TestDependencyGraph_FindNodeFlexible_Tier4_ArtifactOnly(t *testing.T) {
	g := NewDependencyGraph()
	root := g.SetRoot(maven.NewID("com.example", "root", "1.0"))
	g.AddNode(maven.NewID("org.unique", "unique-lib", "1.0"), "compile", root)

	// both groupId and version differ
	found := g.FindNodeFlexible(maven.NewID("com.other", "unique-lib", "99.0"))
	require.NotNil(t, found)
	assert.Equal(t, "org.unique", found.ID.GroupID)
}

func TestDependencyGraph_FindNodeFlexible_NotFound(t *testing.T) {
	g := NewDependencyGraph()
	g.SetRoot(maven.NewID("com.example", "root", "1.0"))

	found := g.FindNodeFlexible(maven.NewID("org.nonexistent", "nope", "1.0"))
	assert.Nil(t, found)
}

func TestDependencyGraph_FindNodeByMavenID(t *testing.T) {
	g := NewDependencyGraph()
	root := g.SetRoot(maven.NewID("com.example", "root", "1.0"))
	g.AddNode(maven.NewID("org.dep", "child", "2.0"), "compile", root)

	found := g.FindNodeByMavenID(NewMavenID("org.dep", "child", "2.0"))
	require.NotNil(t, found)
	assert.Equal(t, "child", found.ID.ArtifactID)
}

func TestDependencyGraph_BuildFromPOMs_SimpleTree(t *testing.T) {
	ctx := context.Background()

	rootPom := &maven.Project{}
	rootPom.GroupID = strPtr("com.example")
	rootPom.ArtifactID = strPtr("root")
	rootPom.Version = strPtr("1.0")
	rootPom.Dependencies = &[]maven.Dependency{
		{
			GroupID:    strPtr("org.dep"),
			ArtifactID: strPtr("child-a"),
			Version:    strPtr("2.0"),
			Scope:      strPtr("compile"),
		},
	}

	childPom := &maven.Project{}
	childPom.GroupID = strPtr("org.dep")
	childPom.ArtifactID = strPtr("child-a")
	childPom.Version = strPtr("2.0")
	childPom.Dependencies = &[]maven.Dependency{
		{
			GroupID:    strPtr("org.transitive"),
			ArtifactID: strPtr("trans-b"),
			Version:    strPtr("3.0"),
			Scope:      strPtr("runtime"),
		},
	}

	poms := map[string]*maven.Project{
		"com.example:root:1.0": rootPom,
		"org.dep:child-a:2.0":  childPom,
	}

	resolver := maven.NewResolver(nil, maven.DefaultConfig())
	g := NewDependencyGraph()
	rootID := maven.NewID("com.example", "root", "1.0")
	g.BuildFromPOMs(ctx, poms, resolver, rootID, false, DefaultMaxDepth)

	assert.Equal(t, 3, g.Size())

	root := g.FindNode(rootID)
	require.NotNil(t, root)
	assert.Equal(t, 0, root.Depth)

	childA := g.FindNode(maven.NewID("org.dep", "child-a", "2.0"))
	require.NotNil(t, childA)
	assert.Equal(t, 1, childA.Depth)
	assert.Equal(t, "compile", childA.Scope)
	assert.Equal(t, root, childA.Parent)

	transB := g.FindNode(maven.NewID("org.transitive", "trans-b", "3.0"))
	require.NotNil(t, transB)
	assert.Equal(t, 2, transB.Depth)
	assert.Equal(t, "runtime", transB.Scope)
	assert.Equal(t, childA, transB.Parent)
}

func TestDependencyGraph_BuildFromPOMs_DiamondDependency(t *testing.T) {
	ctx := context.Background()

	// root -> A -> C, root -> B -> C
	rootPom := &maven.Project{}
	rootPom.GroupID = strPtr("com.example")
	rootPom.ArtifactID = strPtr("root")
	rootPom.Version = strPtr("1.0")
	rootPom.Dependencies = &[]maven.Dependency{
		{GroupID: strPtr("org.dep"), ArtifactID: strPtr("a"), Version: strPtr("1.0"), Scope: strPtr("compile")},
		{GroupID: strPtr("org.dep"), ArtifactID: strPtr("b"), Version: strPtr("1.0"), Scope: strPtr("compile")},
	}

	pomA := &maven.Project{}
	pomA.GroupID = strPtr("org.dep")
	pomA.ArtifactID = strPtr("a")
	pomA.Version = strPtr("1.0")
	pomA.Dependencies = &[]maven.Dependency{
		{GroupID: strPtr("org.shared"), ArtifactID: strPtr("c"), Version: strPtr("1.0"), Scope: strPtr("compile")},
	}

	pomB := &maven.Project{}
	pomB.GroupID = strPtr("org.dep")
	pomB.ArtifactID = strPtr("b")
	pomB.Version = strPtr("1.0")
	pomB.Dependencies = &[]maven.Dependency{
		{GroupID: strPtr("org.shared"), ArtifactID: strPtr("c"), Version: strPtr("1.0"), Scope: strPtr("compile")},
	}

	poms := map[string]*maven.Project{
		"com.example:root:1.0": rootPom,
		"org.dep:a:1.0":        pomA,
		"org.dep:b:1.0":        pomB,
	}

	resolver := maven.NewResolver(nil, maven.DefaultConfig())
	g := NewDependencyGraph()
	g.BuildFromPOMs(ctx, poms, resolver, maven.NewID("com.example", "root", "1.0"), false, DefaultMaxDepth)

	// C should appear once, first-wins (through A)
	assert.Equal(t, 4, g.Size())

	nodeC := g.FindNode(maven.NewID("org.shared", "c", "1.0"))
	require.NotNil(t, nodeC)
	assert.Equal(t, 2, nodeC.Depth)
}

func TestDependencyGraph_BuildFromPOMs_RespectsMaxDepth(t *testing.T) {
	ctx := context.Background()

	// root -> a -> b -> c (max depth = 2 should cut off c)
	rootPom := &maven.Project{}
	rootPom.GroupID = strPtr("com.example")
	rootPom.ArtifactID = strPtr("root")
	rootPom.Version = strPtr("1.0")
	rootPom.Dependencies = &[]maven.Dependency{
		{GroupID: strPtr("org.dep"), ArtifactID: strPtr("a"), Version: strPtr("1.0"), Scope: strPtr("compile")},
	}

	pomA := &maven.Project{}
	pomA.GroupID = strPtr("org.dep")
	pomA.ArtifactID = strPtr("a")
	pomA.Version = strPtr("1.0")
	pomA.Dependencies = &[]maven.Dependency{
		{GroupID: strPtr("org.dep"), ArtifactID: strPtr("b"), Version: strPtr("1.0"), Scope: strPtr("compile")},
	}

	pomB := &maven.Project{}
	pomB.GroupID = strPtr("org.dep")
	pomB.ArtifactID = strPtr("b")
	pomB.Version = strPtr("1.0")
	pomB.Dependencies = &[]maven.Dependency{
		{GroupID: strPtr("org.dep"), ArtifactID: strPtr("c"), Version: strPtr("1.0"), Scope: strPtr("compile")},
	}

	poms := map[string]*maven.Project{
		"com.example:root:1.0": rootPom,
		"org.dep:a:1.0":        pomA,
		"org.dep:b:1.0":        pomB,
	}

	resolver := maven.NewResolver(nil, maven.DefaultConfig())
	g := NewDependencyGraph()
	g.BuildFromPOMs(ctx, poms, resolver, maven.NewID("com.example", "root", "1.0"), false, 2)

	// root + a + b = 3 (c cut off at maxDepth=2)
	assert.Equal(t, 3, g.Size())
	assert.Nil(t, g.FindNode(maven.NewID("org.dep", "c", "1.0")))
}

func TestDependencyGraph_BuildFromPOMs_CycleDetection(t *testing.T) {
	ctx := context.Background()

	// root -> a -> b -> a (cycle)
	rootPom := &maven.Project{}
	rootPom.GroupID = strPtr("com.example")
	rootPom.ArtifactID = strPtr("root")
	rootPom.Version = strPtr("1.0")
	rootPom.Dependencies = &[]maven.Dependency{
		{GroupID: strPtr("org.dep"), ArtifactID: strPtr("a"), Version: strPtr("1.0"), Scope: strPtr("compile")},
	}

	pomA := &maven.Project{}
	pomA.GroupID = strPtr("org.dep")
	pomA.ArtifactID = strPtr("a")
	pomA.Version = strPtr("1.0")
	pomA.Dependencies = &[]maven.Dependency{
		{GroupID: strPtr("org.dep"), ArtifactID: strPtr("b"), Version: strPtr("1.0"), Scope: strPtr("compile")},
	}

	pomB := &maven.Project{}
	pomB.GroupID = strPtr("org.dep")
	pomB.ArtifactID = strPtr("b")
	pomB.Version = strPtr("1.0")
	pomB.Dependencies = &[]maven.Dependency{
		{GroupID: strPtr("org.dep"), ArtifactID: strPtr("a"), Version: strPtr("1.0"), Scope: strPtr("compile")},
	}

	poms := map[string]*maven.Project{
		"com.example:root:1.0": rootPom,
		"org.dep:a:1.0":        pomA,
		"org.dep:b:1.0":        pomB,
	}

	resolver := maven.NewResolver(nil, maven.DefaultConfig())
	g := NewDependencyGraph()
	g.BuildFromPOMs(ctx, poms, resolver, maven.NewID("com.example", "root", "1.0"), false, DefaultMaxDepth)

	// Should complete without infinite loop: root + a + b = 3
	assert.Equal(t, 3, g.Size())
}

func strPtr(s string) *string {
	return &s
}

