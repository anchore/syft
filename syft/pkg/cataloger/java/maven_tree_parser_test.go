package java

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseMavenTreeLine_RootNode(t *testing.T) {
	node := parseMavenTreeLine("com.example:my-app:jar:1.0.0")
	require.NotNil(t, node)
	assert.Equal(t, "com.example", node.GroupID)
	assert.Equal(t, "my-app", node.ArtifactID)
	assert.Equal(t, "jar", node.Packaging)
	assert.Equal(t, "1.0.0", node.Version)
	assert.Empty(t, node.Scope)
	assert.Equal(t, 0, node.Depth)
}

func TestParseMavenTreeLine_DirectDependency(t *testing.T) {
	node := parseMavenTreeLine("+- org.springframework:spring-core:jar:5.3.0:compile")
	require.NotNil(t, node)
	assert.Equal(t, "org.springframework", node.GroupID)
	assert.Equal(t, "spring-core", node.ArtifactID)
	assert.Equal(t, "jar", node.Packaging)
	assert.Equal(t, "5.3.0", node.Version)
	assert.Equal(t, "compile", node.Scope)
	assert.Equal(t, 1, node.Depth)
}

func TestParseMavenTreeLine_NestedDependency(t *testing.T) {
	node := parseMavenTreeLine("|  +- org.springframework:spring-jcl:jar:5.3.0:compile")
	require.NotNil(t, node)
	assert.Equal(t, "spring-jcl", node.ArtifactID)
	assert.Equal(t, "compile", node.Scope)
	assert.Equal(t, 2, node.Depth)
}

func TestParseMavenTreeLine_LastChild(t *testing.T) {
	node := parseMavenTreeLine("|  \\- jakarta.annotation:jakarta.annotation-api:jar:2.1.1:compile")
	require.NotNil(t, node)
	assert.Equal(t, "jakarta.annotation-api", node.ArtifactID)
	assert.Equal(t, 2, node.Depth)
}

func TestParseMavenTreeLine_DeepNesting(t *testing.T) {
	// 4 levels deep: |  |  |  \-
	node := parseMavenTreeLine("|  |  |  \\- org.ow2.asm:asm-commons:jar:9.6:compile")
	require.NotNil(t, node)
	assert.Equal(t, "asm-commons", node.ArtifactID)
	assert.Equal(t, 4, node.Depth)
}

func TestParseMavenTreeLine_WithClassifier(t *testing.T) {
	node := parseMavenTreeLine("+- io.netty:netty-transport-native-epoll:jar:linux-x86_64:4.1.100:compile")
	require.NotNil(t, node)
	assert.Equal(t, "io.netty", node.GroupID)
	assert.Equal(t, "netty-transport-native-epoll", node.ArtifactID)
	assert.Equal(t, "jar", node.Packaging)
	assert.Equal(t, "4.1.100", node.Version)
	assert.Equal(t, "compile", node.Scope)
	assert.Equal(t, 1, node.Depth)
}

func TestParseMavenTreeLine_Optional(t *testing.T) {
	node := parseMavenTreeLine("+- com.google.code.findbugs:jsr305:jar:3.0.2:compile (optional)")
	require.NotNil(t, node)
	assert.Equal(t, "jsr305", node.ArtifactID)
	assert.Equal(t, "3.0.2", node.Version)
	assert.Equal(t, "compile", node.Scope)
	assert.True(t, node.Optional)
}

func TestParseMavenTreeLine_ManagedScope(t *testing.T) {
	node := parseMavenTreeLine("|  +- commons-io:commons-io:jar:2.11.0:compile (scope managed from runtime)")
	require.NotNil(t, node)
	assert.Equal(t, "commons-io", node.ArtifactID)
	assert.Equal(t, "2.11.0", node.Version)
	assert.Equal(t, "compile", node.Scope)
	assert.False(t, node.Optional)
}

func TestParseMavenTreeLine_PomPackaging(t *testing.T) {
	node := parseMavenTreeLine("+- org.springframework.boot:spring-boot-starter:pom:3.5.9:compile")
	require.NotNil(t, node)
	assert.Equal(t, "pom", node.Packaging)
	assert.Equal(t, "spring-boot-starter", node.ArtifactID)
}

func TestParseMavenTreeLine_Malformed(t *testing.T) {
	tests := []struct {
		name string
		line string
	}{
		{"too few parts", "+- groupId:artifactId"},
		{"too many parts", "+- a:b:c:d:e:f:g"},
		{"empty groupId", "+- :artifactId:jar:1.0:compile"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := parseMavenTreeLine(tt.line)
			assert.Nil(t, node)
		})
	}
}

func TestIsMavenOutputNoise(t *testing.T) {
	noiseLines := []string{
		"[INFO] --- dependency:3.6.0:tree (default-cli) @ my-app ---",
		"[WARNING] Some warning",
		"[ERROR] Some error",
		"[DEBUG] Debug output",
		"--- maven-dependency-plugin:3.6.0:tree ---",
		"Downloaded from central: https://repo.maven.apache.org/...",
		"Downloading from central: https://repo.maven.apache.org/...",
		"Progress (1): some-artifact.pom",
	}
	for _, line := range noiseLines {
		assert.True(t, isMavenOutputNoise(line), "expected noise: %s", line)
	}

	validLines := []string{
		"com.example:my-app:jar:1.0.0",
		"+- org.dep:child:jar:2.0:compile",
		"|  \\- org.dep:grandchild:jar:3.0:runtime",
	}
	for _, line := range validLines {
		assert.False(t, isMavenOutputNoise(line), "expected NOT noise: %s", line)
	}
}

func TestExtractDepthAndCoordinates(t *testing.T) {
	tests := []struct {
		line          string
		expectedDepth int
		expectedCoord string
	}{
		{
			"com.example:my-app:jar:1.0.0",
			0,
			"com.example:my-app:jar:1.0.0",
		},
		{
			"+- org.dep:child:jar:2.0:compile",
			1,
			"org.dep:child:jar:2.0:compile",
		},
		{
			"\\- org.dep:last:jar:2.0:compile",
			1,
			"org.dep:last:jar:2.0:compile",
		},
		{
			"|  +- org.dep:nested:jar:3.0:compile",
			2,
			"org.dep:nested:jar:3.0:compile",
		},
		{
			"|  \\- org.dep:nested-last:jar:3.0:compile",
			2,
			"org.dep:nested-last:jar:3.0:compile",
		},
		{
			"|  |  +- org.dep:deep:jar:4.0:compile",
			3,
			"org.dep:deep:jar:4.0:compile",
		},
		{
			"   \\- org.dep:spaced:jar:2.0:compile",
			2,
			"org.dep:spaced:jar:2.0:compile",
		},
	}
	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			depth, coords := extractDepthAndCoordinates(tt.line)
			assert.Equal(t, tt.expectedDepth, depth)
			assert.Equal(t, tt.expectedCoord, coords)
		})
	}
}

func TestParseMavenDependencyTree_FullTree(t *testing.T) {
	input := `com.example:my-app:jar:1.0.0
+- org.springframework:spring-core:jar:5.3.0:compile
|  \- org.springframework:spring-jcl:jar:5.3.0:compile
+- com.fasterxml.jackson.core:jackson-databind:jar:2.13.0:compile
|  +- com.fasterxml.jackson.core:jackson-core:jar:2.13.0:compile
|  \- com.fasterxml.jackson.core:jackson-annotations:jar:2.13.0:compile
\- org.junit.jupiter:junit-jupiter:jar:5.8.0:test
   \- org.junit.jupiter:junit-jupiter-api:jar:5.8.0:test
`

	tree, err := ParseMavenDependencyTree(strings.NewReader(input))
	require.NoError(t, err)
	require.NotNil(t, tree.Root)

	// root
	assert.Equal(t, "my-app", tree.Root.ArtifactID)
	assert.Equal(t, 0, tree.Root.Depth)
	assert.Nil(t, tree.Root.Parent)
	assert.Len(t, tree.Root.Children, 3)

	// direct deps
	springCore := tree.Root.Children[0]
	assert.Equal(t, "spring-core", springCore.ArtifactID)
	assert.Equal(t, 1, springCore.Depth)
	assert.Equal(t, "compile", springCore.Scope)
	assert.Equal(t, tree.Root, springCore.Parent)
	assert.Len(t, springCore.Children, 1)

	// transitive
	springJcl := springCore.Children[0]
	assert.Equal(t, "spring-jcl", springJcl.ArtifactID)
	assert.Equal(t, 2, springJcl.Depth)
	assert.Equal(t, springCore, springJcl.Parent)

	// jackson-databind with 2 children
	databind := tree.Root.Children[1]
	assert.Equal(t, "jackson-databind", databind.ArtifactID)
	assert.Len(t, databind.Children, 2)

	// test scope last child
	junit := tree.Root.Children[2]
	assert.Equal(t, "junit-jupiter", junit.ArtifactID)
	assert.Equal(t, "test", junit.Scope)
	assert.Len(t, junit.Children, 1)

	// total nodes
	assert.Len(t, tree.NodeMap, 8)
}

func TestParseMavenDependencyTree_EmptyInput(t *testing.T) {
	_, err := ParseMavenDependencyTree(strings.NewReader(""))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no root node found")
}

func TestParseMavenDependencyTree_OnlyNoise(t *testing.T) {
	input := `[INFO] --- dependency:3.6.0:tree ---
[INFO]
[INFO] BUILD SUCCESS
`
	_, err := ParseMavenDependencyTree(strings.NewReader(input))
	assert.Error(t, err)
}

func TestParseMavenDependencyTree_WithNoiseLines(t *testing.T) {
	input := `[INFO] --- dependency:3.6.0:tree ---
com.example:my-app:jar:1.0.0
[INFO]
+- org.dep:child:jar:2.0:compile
[INFO] BUILD SUCCESS
`
	tree, err := ParseMavenDependencyTree(strings.NewReader(input))
	require.NoError(t, err)
	assert.Equal(t, "my-app", tree.Root.ArtifactID)
	assert.Len(t, tree.Root.Children, 1)
}

func TestParseMavenDependencyTreeFile(t *testing.T) {
	tree, err := ParseMavenDependencyTreeFile("testdata/maven-dependency-tree.txt")
	require.NoError(t, err)
	require.NotNil(t, tree.Root)

	assert.Equal(t, "my-app", tree.Root.ArtifactID)
	assert.Equal(t, "com.example", tree.Root.GroupID)
	assert.Equal(t, "1.0.0", tree.Root.Version)

	// 5 direct deps: spring-boot-starter, jackson-databind, spring-core, micrometer-core, junit-jupiter
	assert.Len(t, tree.Root.Children, 5)

	// deepest node: junit-platform-engine at depth 3
	engine := tree.NodeMap["org.junit.platform:junit-platform-engine:1.11.6"]
	require.NotNil(t, engine)
	assert.Equal(t, 3, engine.Depth)
	assert.Equal(t, "test", engine.Scope)

	// total nodes in fixture
	assert.Len(t, tree.NodeMap, 16)
}

func TestParseMavenDependencyTreeFile_NotFound(t *testing.T) {
	_, err := ParseMavenDependencyTreeFile("testdata/nonexistent-file.txt")
	assert.Error(t, err)
}

func TestMavenTree_ToInternalGraph(t *testing.T) {
	input := `com.example:root:jar:1.0
+- org.dep:direct-a:jar:2.0:compile
|  \- org.dep:transitive-b:jar:3.0:runtime
\- org.dep:direct-c:jar:4.0:test
`

	tree, err := ParseMavenDependencyTree(strings.NewReader(input))
	require.NoError(t, err)

	graph := tree.ToInternalGraph()
	require.NotNil(t, graph)
	assert.Equal(t, 4, graph.Size())

	// root at depth 0
	root := graph.Root
	require.NotNil(t, root)
	assert.Equal(t, "root", root.ID.ArtifactID)
	assert.Equal(t, 0, root.Depth)

	// direct-a at depth 1
	directA := graph.FindNode(tree.Root.Children[0].id())
	require.NotNil(t, directA)
	assert.Equal(t, 1, directA.Depth)
	assert.Equal(t, "compile", directA.Scope)
	assert.Equal(t, root, directA.Parent)

	// transitive-b at depth 2
	transB := graph.FindNode(tree.Root.Children[0].Children[0].id())
	require.NotNil(t, transB)
	assert.Equal(t, 2, transB.Depth)
	assert.Equal(t, "runtime", transB.Scope)
	assert.Equal(t, directA, transB.Parent)

	// direct-c at depth 1
	directC := graph.FindNode(tree.Root.Children[1].id())
	require.NotNil(t, directC)
	assert.Equal(t, 1, directC.Depth)
	assert.Equal(t, "test", directC.Scope)
}

func TestMavenTree_ToInternalGraph_EmptyRoot(t *testing.T) {
	tree := &MavenTree{}
	graph := tree.ToInternalGraph()
	assert.NotNil(t, graph)
	assert.Equal(t, 0, graph.Size())
}

func BenchmarkParseMavenDependencyTree(b *testing.B) {
	// build a moderately sized tree input (~100 nodes)
	var sb strings.Builder
	sb.WriteString("com.example:root:jar:1.0.0\n")
	for i := 0; i < 20; i++ {
		sb.WriteString(fmt.Sprintf("+- org.dep:direct-%d:jar:%d.0:compile\n", i, i))
		for j := 0; j < 4; j++ {
			sb.WriteString(fmt.Sprintf("|  +- org.dep:trans-%d-%d:jar:%d.%d:compile\n", i, j, i, j))
		}
	}
	input := sb.String()

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_, _ = ParseMavenDependencyTree(strings.NewReader(input))
	}
}
