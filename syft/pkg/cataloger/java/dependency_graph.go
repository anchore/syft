package java

import (
	"context"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg/cataloger/java/internal/maven"
)

// DependencyNode represents a single node in the Maven dependency tree.
type DependencyNode struct {
	ID       maven.ID
	Scope    string
	Parent   *DependencyNode
	Children []*DependencyNode
}

// Depth computes this node's depth by walking the parent chain.
func (n *DependencyNode) Depth() int {
	depth := 0
	current := n.Parent
	for current != nil {
		depth++
		current = current.Parent
	}
	return depth
}

// DependencyGraph holds the tree of Maven dependencies built from embedded POM files.
type DependencyGraph struct {
	Root    *DependencyNode
	NodeMap map[maven.ID]*DependencyNode
}

// NewDependencyGraph creates an empty dependency graph.
func NewDependencyGraph() *DependencyGraph {
	return &DependencyGraph{
		NodeMap: make(map[maven.ID]*DependencyNode),
	}
}

// SetRoot creates and sets the root node of the graph.
func (g *DependencyGraph) SetRoot(id maven.ID) *DependencyNode {
	node := &DependencyNode{ID: id}
	g.Root = node
	g.NodeMap[id] = node
	return node
}

// AddNode adds a dependency node with the given parent.
func (g *DependencyGraph) AddNode(id maven.ID, scope string, parent *DependencyNode) *DependencyNode {
	if _, exists := g.NodeMap[id]; exists {
		return g.NodeMap[id]
	}
	node := &DependencyNode{
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
func (g *DependencyGraph) FindNode(id maven.ID) *DependencyNode {
	return g.NodeMap[id]
}

// Size returns the number of nodes in the graph.
func (g *DependencyGraph) Size() int {
	return len(g.NodeMap)
}

// BuildFromPOMs constructs the dependency graph by walking embedded POM dependency sections.
func (g *DependencyGraph) BuildFromPOMs(
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

	rootNode := g.SetRoot(rootID)

	visited := map[maven.ID]bool{rootID: true}
	g.buildFromPOM(ctx, poms, resolver, rootPom, rootNode, visited, resolveTransitive, maxDepth)
}

func (g *DependencyGraph) buildFromPOM(
	ctx context.Context,
	poms map[maven.ID]*maven.Project,
	resolver *maven.Resolver,
	pom *maven.Project,
	parentNode *DependencyNode,
	visited map[maven.ID]bool,
	resolveTransitive bool,
	maxDepth int,
) {
	if parentNode.Depth() >= maxDepth {
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

		node := g.AddNode(depID, scope, parentNode)

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
