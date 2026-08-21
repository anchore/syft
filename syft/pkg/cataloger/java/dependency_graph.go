package java

import (
	"context"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg/cataloger/java/internal/maven"
)

// DependencyNode represents a single node in the Maven dependency tree.
type dependencyNode struct {
	ID       maven.ID
	Scope    string
	Parent   *dependencyNode
	Children []*dependencyNode
}

// Depth computes this node's depth by walking the parent chain.
func (n *dependencyNode) depth() int {
	depth := 0
	current := n.Parent
	for current != nil {
		depth++
		current = current.Parent
	}
	return depth
}

// DependencyGraph holds the tree of Maven dependencies built from embedded POM files.
type dependencyGraph struct {
	Root    *dependencyNode
	NodeMap map[maven.ID]*dependencyNode
}

// NewDependencyGraph creates an empty dependency graph.
func newDependencyGraph() *dependencyGraph {
	return &dependencyGraph{
		NodeMap: make(map[maven.ID]*dependencyNode),
	}
}

// SetRoot creates and sets the root node of the graph.
func (g *dependencyGraph) setRoot(id maven.ID) *dependencyNode {
	node := &dependencyNode{ID: id}
	g.Root = node
	g.NodeMap[id] = node
	return node
}

// AddNode adds a dependency node with the given parent.
func (g *dependencyGraph) addNode(id maven.ID, scope string, parent *dependencyNode) *dependencyNode {
	if _, exists := g.NodeMap[id]; exists {
		return g.NodeMap[id]
	}
	node := &dependencyNode{
		ID:     id,
		Scope:  scope,
		Parent: parent,
	}
	if parent != nil {
		parent.Children = append(parent.Children, node)
	}
	g.NodeMap[id] = node
	return node
}

// FindNode looks up a node by exact maven.ID match.
func (g *dependencyGraph) findNode(id maven.ID) *dependencyNode {
	return g.NodeMap[id]
}

// FindNodeByGA looks up a node by groupId and artifactId only, ignoring version.
// This handles version-mismatch scenarios where Maven dependency management resolves
// a different version than what the POM declares.
func (g *dependencyGraph) findNodeByGA(groupID, artifactID string) *dependencyNode {
	for id, node := range g.NodeMap {
		if id.GroupID == groupID && id.ArtifactID == artifactID {
			return node
		}
	}
	return nil
}

// Size returns the number of nodes in the graph.
func (g *dependencyGraph) size() int {
	return len(g.NodeMap)
}

// BuildFromPOMs constructs the dependency graph by walking embedded POM dependency sections.
func (g *dependencyGraph) buildFromPOMs(
	ctx context.Context,
	poms map[maven.ID]*maven.Project,
	resolver *maven.Resolver,
	rootID maven.ID,
	resolveTransitive bool,
	maxDepth int,
) {
	rootPom, exists := poms[rootID]
	if !exists {
		log.WithFields("rootID", rootID).Debug("root POM not found in embedded POMs, skipping graph build")
		return
	}

	rootNode := g.setRoot(rootID)

	visited := map[maven.ID]bool{rootID: true}
	g.buildFromPOM(ctx, poms, resolver, rootPom, rootNode, visited, resolveTransitive, maxDepth)
}

func (g *dependencyGraph) buildFromPOM(
	ctx context.Context,
	poms map[maven.ID]*maven.Project,
	resolver *maven.Resolver,
	pom *maven.Project,
	parentNode *dependencyNode,
	visited map[maven.ID]bool,
	resolveTransitive bool,
	maxDepth int,
) {
	if parentNode.depth() >= maxDepth {
		return
	}

	deps := maven.DirectPomDependencies(pom)
	for i := range deps {
		dep := deps[i]

		depID := resolver.ResolveDependencyID(ctx, pom, dep)
		if depID.GroupID == "" || depID.ArtifactID == "" {
			continue
		}

		if visited[depID] {
			continue
		}

		scope := resolver.ResolveProperty(ctx, pom, dep.Scope)

		node := g.addNode(depID, scope, parentNode)

		if resolveTransitive {
			childPom, childExists := poms[depID]
			if childExists {
				branchVisited := copyVisited(visited)
				branchVisited[depID] = true
				g.buildFromPOM(ctx, poms, resolver, childPom, node, branchVisited, resolveTransitive, maxDepth)
			}
		}
	}
}

func copyVisited(m map[maven.ID]bool) map[maven.ID]bool {
	cp := make(map[maven.ID]bool, len(m))
	for k, v := range m {
		cp[k] = v
	}
	return cp
}
