package java

import (
	"context"
	"fmt"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg/cataloger/java/internal/maven"
)

const DefaultMaxDepth = 10

type DependencyNode struct {
	ID       maven.ID
	Scope    string
	Parent   *DependencyNode
	Children []*DependencyNode
	Depth    int
}

type DependencyGraph struct {
	Root    *DependencyNode
	NodeMap map[string]*DependencyNode
}

func NewDependencyGraph() *DependencyGraph {
	return &DependencyGraph{
		NodeMap: make(map[string]*DependencyNode),
	}
}

func (g *DependencyGraph) SetRoot(id maven.ID) *DependencyNode {
	key := mavenIDKey(id)
	node := &DependencyNode{
		ID:    id,
		Depth: 0,
	}
	g.Root = node
	g.NodeMap[key] = node
	return node
}

func (g *DependencyGraph) AddNode(id maven.ID, scope string, parent *DependencyNode) *DependencyNode {
	key := mavenIDKey(id)
	if existing, ok := g.NodeMap[key]; ok {
		return existing
	}

	depth := 0
	if parent != nil {
		depth = parent.Depth + 1
	}

	node := &DependencyNode{
		ID:     id,
		Scope:  scope,
		Parent: parent,
		Depth:  depth,
	}

	if parent != nil {
		parent.Children = append(parent.Children, node)
	}

	g.NodeMap[key] = node
	return node
}

func (g *DependencyGraph) FindNode(id maven.ID) *DependencyNode {
	return g.NodeMap[mavenIDKey(id)]
}

// FindNodeFlexible performs 4-tier matching to handle version mismatches and groupId changes.
func (g *DependencyGraph) FindNodeFlexible(id maven.ID) *DependencyNode {
	key := mavenIDKey(id)

	// Tier 1: exact match
	if node, ok := g.NodeMap[key]; ok {
		log.WithFields("mavenID", key, "matchType", "exact").Trace("dependency graph: found node")
		return node
	}

	gaKey := id.GroupID + ":" + id.ArtifactID

	// Tier 2: groupId:artifactId (ignore version)
	for k, node := range g.NodeMap {
		parts := strings.SplitN(k, ":", 3)
		if len(parts) >= 2 && parts[0]+":"+parts[1] == gaKey {
			log.WithFields("mavenID", key, "matchType", "groupId:artifactId", "matchedKey", k).Trace("dependency graph: found node")
			return node
		}
	}

	avKey := id.ArtifactID + ":" + id.Version

	// Tier 3: artifactId:version (ignore groupId)
	for k, node := range g.NodeMap {
		parts := strings.SplitN(k, ":", 3)
		if len(parts) == 3 && parts[1]+":"+parts[2] == avKey {
			log.WithFields("mavenID", key, "matchType", "artifactId:version", "matchedKey", k).Trace("dependency graph: found node")
			return node
		}
	}

	// Tier 4: artifactId only
	for k, node := range g.NodeMap {
		parts := strings.SplitN(k, ":", 3)
		if len(parts) >= 2 && parts[1] == id.ArtifactID {
			log.WithFields("mavenID", key, "matchType", "artifactId", "matchedKey", k).Trace("dependency graph: found node")
			return node
		}
	}

	log.WithFields("mavenID", key).Trace("dependency graph: node not found")
	return nil
}

// FindNodeByMavenID is the bridge for external packages using the exported MavenID type.
func (g *DependencyGraph) FindNodeByMavenID(id MavenID) *DependencyNode {
	return g.FindNodeFlexible(id.toInternalID())
}

func (g *DependencyGraph) Size() int {
	return len(g.NodeMap)
}

// BuildFromPOMs builds the dependency graph by recursively walking embedded POMs.
func (g *DependencyGraph) BuildFromPOMs(
	ctx context.Context,
	poms map[string]*maven.Project,
	resolver *maven.Resolver,
	rootID maven.ID,
	resolveTransitive bool,
	maxDepth int,
) {
	g.SetRoot(rootID)

	rootPom := poms[mavenIDKey(rootID)]
	if rootPom == nil && resolveTransitive {
		var err error
		rootPom, err = resolver.FindPom(ctx, rootID.GroupID, rootID.ArtifactID, rootID.Version)
		if err != nil {
			log.WithFields("error", err, "mavenID", mavenIDKey(rootID)).Debug("failed to find root POM for graph building")
		}
	}
	if rootPom == nil {
		return
	}

	visited := make(map[string]bool)
	g.buildFromPOM(ctx, poms, resolver, rootPom, g.Root, visited, resolveTransitive, maxDepth, 0)
}

func (g *DependencyGraph) buildFromPOM(
	ctx context.Context,
	poms map[string]*maven.Project,
	resolver *maven.Resolver,
	pom *maven.Project,
	parentNode *DependencyNode,
	visited map[string]bool,
	resolveTransitive bool,
	maxDepth int,
	currentDepth int,
) {
	if currentDepth >= maxDepth {
		return
	}

	pomKey := mavenIDKey(resolver.ResolveID(ctx, pom))
	if visited[pomKey] {
		return
	}
	visited[pomKey] = true

	for _, dep := range maven.DirectPomDependencies(pom) {
		depID := resolver.ResolveDependencyID(ctx, pom, dep)
		if !depID.Valid() {
			continue
		}

		scope := resolver.ResolveProperty(ctx, pom, dep.Scope)

		depKey := mavenIDKey(depID)
		existing := g.NodeMap[depKey]
		if existing != nil {
			continue
		}

		depNode := g.AddNode(depID, scope, parentNode)

		depPom := poms[depKey]
		if depPom == nil && resolveTransitive {
			var err error
			depPom, err = resolver.FindPom(ctx, depID.GroupID, depID.ArtifactID, depID.Version)
			if err != nil {
				log.WithFields("error", err, "mavenID", depKey).Trace("failed to find dependency POM for graph building")
			}
		}
		if depPom != nil {
			branchVisited := make(map[string]bool, len(visited))
			for k, v := range visited {
				branchVisited[k] = v
			}
			g.buildFromPOM(ctx, poms, resolver, depPom, depNode, branchVisited, resolveTransitive, maxDepth, currentDepth+1)
		}
	}
}

// mavenIDKey returns a colon-separated key for use in the NodeMap.
func mavenIDKey(id maven.ID) string {
	return fmt.Sprintf("%s:%s:%s", id.GroupID, id.ArtifactID, id.Version)
}
