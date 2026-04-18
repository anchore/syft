package java

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/anchore/syft/syft/pkg/cataloger/java/internal/maven"
)

// MavenTreeNode represents a single node in a parsed Maven dependency tree.
type MavenTreeNode struct {
	GroupID    string
	ArtifactID string
	Version    string
	Packaging  string
	Scope      string
	Optional   bool
	Parent     *MavenTreeNode
	Children   []*MavenTreeNode
	Depth      int
}

func (n *MavenTreeNode) id() maven.ID {
	return maven.NewID(n.GroupID, n.ArtifactID, n.Version)
}

// MavenTree represents the full parsed Maven dependency tree.
type MavenTree struct {
	Root    *MavenTreeNode
	NodeMap map[string]*MavenTreeNode
}

func newMavenTree() *MavenTree {
	return &MavenTree{
		NodeMap: make(map[string]*MavenTreeNode),
	}
}

// ParseMavenDependencyTreeFile parses a Maven dependency tree from a file path.
func ParseMavenDependencyTreeFile(filePath string) (*MavenTree, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("unable to open Maven dependency tree file: %w", err)
	}
	defer f.Close()
	return ParseMavenDependencyTree(f)
}

// ParseMavenDependencyTree parses the text output of `mvn dependency:tree`.
func ParseMavenDependencyTree(reader io.Reader) (*MavenTree, error) {
	tree := newMavenTree()
	var nodeStack []*MavenTreeNode

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := stripMavenLogPrefix(scanner.Text())

		if strings.TrimSpace(line) == "" {
			continue
		}
		if isMavenOutputNoise(line) {
			continue
		}

		node := parseMavenTreeLine(line)
		if node == nil {
			continue
		}

		key := fmt.Sprintf("%s:%s:%s", node.GroupID, node.ArtifactID, node.Version)
		tree.NodeMap[key] = node

		if node.Depth == 0 {
			tree.Root = node
			nodeStack = []*MavenTreeNode{node}
		} else {
			// extend stack capacity if needed
			for len(nodeStack) <= node.Depth {
				nodeStack = append(nodeStack, nil)
			}

			parent := nodeStack[node.Depth-1]
			if parent != nil {
				node.Parent = parent
				parent.Children = append(parent.Children, node)
			}
			nodeStack[node.Depth] = node
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading Maven dependency tree: %w", err)
	}

	if tree.Root == nil {
		return nil, fmt.Errorf("no root node found in Maven dependency tree")
	}

	return tree, nil
}

// parseMavenTreeLine parses a single line from Maven dependency tree output.
func parseMavenTreeLine(line string) *MavenTreeNode {
	depth, coords := extractDepthAndCoordinates(line)
	if coords == "" {
		return nil
	}

	// strip annotations like "(scope managed from X.Y.Z)"
	if idx := strings.Index(coords, " ("); idx != -1 {
		suffix := coords[idx:]
		if strings.Contains(suffix, "managed from") {
			coords = coords[:idx]
		}
	}

	// check and strip "(optional)" suffix
	optional := false
	if strings.HasSuffix(coords, " (optional)") {
		optional = true
		coords = strings.TrimSuffix(coords, " (optional)")
	}

	parts := strings.Split(coords, ":")
	node := &MavenTreeNode{
		Depth:    depth,
		Optional: optional,
	}

	switch len(parts) {
	case 4:
		// root format: groupId:artifactId:packaging:version
		node.GroupID = parts[0]
		node.ArtifactID = parts[1]
		node.Packaging = parts[2]
		node.Version = parts[3]
	case 5:
		// standard: groupId:artifactId:packaging:version:scope
		node.GroupID = parts[0]
		node.ArtifactID = parts[1]
		node.Packaging = parts[2]
		node.Version = parts[3]
		node.Scope = parts[4]
	case 6:
		// with classifier: groupId:artifactId:packaging:classifier:version:scope
		node.GroupID = parts[0]
		node.ArtifactID = parts[1]
		node.Packaging = parts[2]
		// parts[3] is classifier — not stored but consumed
		node.Version = parts[4]
		node.Scope = parts[5]
	default:
		return nil
	}

	if node.GroupID == "" || node.ArtifactID == "" || node.Version == "" {
		return nil
	}

	return node
}

// extractDepthAndCoordinates parses tree-drawing characters to determine depth
// and extracts the Maven coordinate string that follows.
func extractDepthAndCoordinates(line string) (int, string) {
	depth := 0
	i := 0

	for i < len(line) {
		remaining := line[i:]

		// child branch: "+- "
		if strings.HasPrefix(remaining, "+- ") {
			depth++
			return depth, line[i+3:]
		}

		// last child: "\- "
		if strings.HasPrefix(remaining, "\\- ") {
			depth++
			return depth, line[i+3:]
		}

		// continuation: "|  " (pipe + 2 spaces)
		if strings.HasPrefix(remaining, "|  ") {
			depth++
			i += 3
			continue
		}

		// spacing: "   " (3 spaces)
		if strings.HasPrefix(remaining, "   ") {
			depth++
			i += 3
			continue
		}

		// no tree prefix — this is a root node or unrecognized format
		break
	}

	// if we consumed nothing, this is the root line (depth 0)
	if i == 0 {
		return 0, strings.TrimSpace(line)
	}

	// if we consumed some prefix but didn't hit "+- " or "\- ", skip the line
	return depth, ""
}

// stripMavenLogPrefix removes a leading Maven log-level prefix such as "[INFO] "
// from a line so the remaining content can be parsed as tree data.
func stripMavenLogPrefix(line string) string {
	trimmed := strings.TrimSpace(line)
	for _, prefix := range []string{"[INFO] ", "[WARNING] ", "[ERROR] ", "[DEBUG] "} {
		if strings.HasPrefix(trimmed, prefix) {
			return trimmed[len(prefix):]
		}
	}
	return line
}

// isMavenOutputNoise returns true for lines that are Maven console output, not tree data.
// It expects the log-level prefix (e.g. "[INFO] ") to already be stripped.
func isMavenOutputNoise(line string) bool {
	trimmed := strings.TrimSpace(line)
	prefixes := []string{
		"---",
		"Downloaded",
		"Downloading",
		"Progress",
		"BUILD",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(trimmed, p) {
			return true
		}
	}
	return false
}

// ToInternalGraph converts the parsed MavenTree into a DependencyGraph.
func (t *MavenTree) ToInternalGraph() *DependencyGraph {
	if t.Root == nil {
		return NewDependencyGraph()
	}

	graph := NewDependencyGraph()
	rootNode := graph.SetRoot(t.Root.id())
	rootNode.Scope = t.Root.Scope

	convertChildrenToGraph(t.Root, rootNode, graph)

	return graph
}

func convertChildrenToGraph(treeNode *MavenTreeNode, graphParent *DependencyNode, graph *DependencyGraph) {
	for _, child := range treeNode.Children {
		graphChild := graph.AddNode(child.id(), child.Scope, graphParent)
		convertChildrenToGraph(child, graphChild, graph)
	}
}
