package rust

import (
	"context"
	"fmt"
	"path"
	"path/filepath"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/pelletier/go-toml"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
)

type cargoLockAdapter struct {
	cfg CatalogerConfig
}

func (a cargoLockAdapter) parseCargoLock(ctx context.Context, resolver file.Resolver, env *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	pkgs, relationships, err := parseCargoLock(ctx, resolver, env, reader)
	if err != nil || a.cfg.IncludeDevDependencies || resolver == nil {
		return pkgs, relationships, err
	}
	manifests, roots, err := cargoManifests(resolver, reader.Location)
	if err != nil {
		log.Warnf("unable to exclude Rust development dependencies from %s: %v", reader.RealPath, err)
		return pkgs, relationships, nil
	}
	pkgs = excludeCargoDevDependencies(pkgs, manifests, roots)
	return pkgs, dependency.Resolve(dependencySpecification, pkgs), nil
}

// cargoManifests reads local manifests through the source resolver. Cargo.lock
// has no dependency kinds, so missing manifests must never imply dev-only use.
func cargoManifests(resolver file.Resolver, lock file.Location) (map[string]*toml.Tree, map[string]bool, error) {
	rootDir := path.Dir(lock.RealPath)
	rootLocation := resolver.RelativeFileByPath(lock, path.Join(rootDir, "Cargo.toml"))
	if rootLocation == nil {
		return nil, nil, fmt.Errorf("Cargo.toml is missing")
	}
	root, err := readCargoManifest(resolver, *rootLocation)
	if err != nil {
		return nil, nil, err
	}
	locations, err := cargoWorkspaceLocations(resolver, root, rootDir)
	if err != nil {
		return nil, nil, err
	}
	locations = append(locations, *rootLocation)
	manifests := make(map[string]*toml.Tree)
	roots := make(map[string]bool)
	seenPaths := make(map[string]bool)
	discovered := []file.Location{*rootLocation}
	for len(locations) > 0 {
		location := locations[0]
		locations = locations[1:]
		if seenPaths[location.RealPath] {
			continue
		}
		seenPaths[location.RealPath] = true
		discovered = append(discovered, location)
		tree, err := readCargoManifest(resolver, location)
		if err != nil {
			return nil, nil, err
		}
		isRoot := cargoManifestIsRoot(resolver, root, tree, *rootLocation, location)
		for _, dependencyPath := range cargoManifestPaths(tree, root, location.RealPath, rootLocation.RealPath) {
			if dependencyLocation := resolver.RelativeFileByPath(location, dependencyPath); dependencyLocation != nil {
				locations = append(locations, *dependencyLocation)
			}
		}
		key := cargoManifestIdentity(tree, root)
		if key == "" {
			continue
		}
		// An unrelated project with the same local package identity is
		// ambiguous. Retain its dependencies rather than guessing a scope.
		if _, exists := manifests[key]; exists {
			manifests[key] = nil
			roots[key] = true
			continue
		}
		if workspace, ok := root.Get("workspace.dependencies").(*toml.Tree); ok {
			tree.Set("workspace.dependencies", workspace)
		}
		manifests[key] = tree
		roots[key] = roots[key] || isRoot
	}
	if err := applyCargoProjectPatches(resolver, discovered, root, manifests); err != nil {
		return nil, nil, err
	}
	return manifests, roots, nil
}

func applyCargoProjectPatches(resolver file.Resolver, locations []file.Location, root *toml.Tree, manifests map[string]*toml.Tree) error {
	patches, err := cargoProjectConfigurationPatches(resolver, locations)
	if err != nil {
		return err
	}
	if patches == nil {
		patches, _ = root.Get("patch").(*toml.Tree)
	}
	for _, tree := range manifests {
		if tree != nil && patches != nil {
			tree.Set("patch", patches)
		}
		if tree != nil && root.Get("replace") != nil {
			// Cargo applies root replacements to every workspace member.
			tree.Set("replace", root.Get("replace"))
		}
	}
	return nil
}

func readCargoManifest(resolver file.Resolver, location file.Location) (*toml.Tree, error) {
	r, err := resolver.FileContentsByLocation(location)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return toml.LoadReader(r)
}

func cargoConfigurationPatches(resolver file.Resolver, root file.Location) (*toml.Tree, error) {
	for dir := path.Dir(root.RealPath); ; dir = path.Dir(dir) {
		for _, name := range []string{"config", "config.toml"} {
			location := resolver.RelativeFileByPath(root, path.Join(dir, ".cargo", name))
			if location == nil {
				continue
			}
			config, err := readCargoManifest(resolver, *location)
			if err != nil {
				return nil, fmt.Errorf("unable to read Cargo configuration %s: %w", location.RealPath, err)
			}
			if patches, ok := config.Get("patch").(*toml.Tree); ok {
				return patches, nil
			}
		}
		if path.Dir(dir) == dir {
			break
		}
	}
	return nil, nil
}

// The lockfile does not record Cargo's invocation directory. A patch from a
// member or its subdirectories can affect the entire workspace, so collect
// source uncertainty across the project before classifying any dependency.
func cargoProjectConfigurationPatches(resolver file.Resolver, locations []file.Location) (*toml.Tree, error) {
	var searched []string
	for _, location := range locations {
		dir := path.Dir(location.RealPath)
		if cargoConfigurationDirectoryCovered(dir, searched) {
			continue
		}
		searched = append(searched, dir)
		patches, err := cargoConfigurationPatches(resolver, location)
		if err != nil || patches != nil {
			return patches, err
		}
		configs, err := resolver.FilesByGlob(path.Join(dir, "**/.cargo/config"), path.Join(dir, "**/.cargo/config.toml"))
		if err != nil {
			return nil, err
		}
		for _, configLocation := range configs {
			config, err := readCargoManifest(resolver, configLocation)
			if err != nil {
				return nil, fmt.Errorf("unable to read Cargo configuration %s: %w", configLocation.RealPath, err)
			}
			if patches, ok := config.Get("patch").(*toml.Tree); ok {
				return patches, nil
			}
		}
	}
	return nil, nil
}

func cargoConfigurationDirectoryCovered(dir string, searched []string) bool {
	for _, root := range searched {
		relative, err := filepath.Rel(root, dir)
		if err == nil && relative != ".." && !strings.HasPrefix(filepath.ToSlash(relative), "../") {
			return true
		}
	}
	return false
}

func cargoWorkspaceLocations(resolver file.Resolver, root *toml.Tree, rootDir string) ([]file.Location, error) {
	var locations []file.Location
	members, _ := root.Get("workspace.members").([]interface{})
	for _, member := range members {
		pattern, ok := member.(string)
		if !ok {
			continue
		}
		matches, err := resolver.FilesByGlob(path.Join(rootDir, pattern, "Cargo.toml"))
		if err != nil {
			return nil, err
		}
		for _, match := range matches {
			relative, err := filepath.Rel(rootDir, path.Dir(match.RealPath))
			if err == nil && cargoWorkspaceMember(root, filepath.ToSlash(relative)) {
				locations = append(locations, match)
			}
		}
	}
	return locations, nil
}

func cargoManifestIdentity(tree, workspace *toml.Tree) string {
	name, _ := tree.Get("package.name").(string)
	version, _ := tree.Get("package.version").(string)
	if tree.Get("package.version") == nil {
		version = "0.0.0"
	} else if tree.Get("package.version.workspace") == true {
		version, _ = workspace.Get("workspace.package.version").(string)
	}
	if name == "" || version == "" {
		return ""
	}
	return name + " " + version
}

func cargoManifestPaths(tree, workspace *toml.Tree, manifestPath, workspacePath string) []string {
	var paths []string
	for _, table := range cargoDependencyTables(tree) {
		for _, section := range []string{"dependencies", "build-dependencies", "dev-dependencies"} {
			deps, ok := table.GetPath([]string{section}).(*toml.Tree)
			if !ok {
				continue
			}
			for _, alias := range deps.Keys() {
				entry, inherited := cargoDependencyEntry(deps, workspace, alias)
				if entry == nil {
					continue
				}
				base := path.Dir(manifestPath)
				if inherited {
					base = path.Dir(workspacePath)
				}
				if dependencyPath, ok := entry.Get("path").(string); ok {
					paths = append(paths, path.Join(base, dependencyPath, "Cargo.toml"))
				}
			}
		}
	}
	return paths
}

func cargoDependencyEntry(deps, workspace *toml.Tree, alias string) (*toml.Tree, bool) {
	entry, ok := deps.GetPath([]string{alias}).(*toml.Tree)
	if !ok {
		return nil, false
	}
	inherited := entry.Get("workspace") == true
	if inherited {
		entry, _ = workspace.GetPath([]string{"workspace", "dependencies", alias}).(*toml.Tree)
	}
	return entry, inherited
}

func cargoWorkspaceMember(root *toml.Tree, relative string) bool {
	return cargoWorkspaceMatches(root.Get("workspace.members"), relative) && !cargoWorkspaceMatches(root.Get("workspace.exclude"), relative)
}

func cargoWorkspaceMatches(value interface{}, relative string) bool {
	patterns, _ := value.([]interface{})
	for _, pattern := range patterns {
		if pattern, ok := pattern.(string); ok {
			if match, _ := doublestar.Match(path.Clean(pattern), path.Clean(relative)); match {
				return true
			}
		}
	}
	return false
}

func cargoManifestIsRoot(resolver file.Resolver, root, tree *toml.Tree, rootLocation, location file.Location) bool {
	if location.RealPath == rootLocation.RealPath {
		return true
	}
	rootDir := path.Dir(rootLocation.RealPath)
	relative, err := filepath.Rel(rootDir, path.Dir(location.RealPath))
	if err != nil {
		return true // uncertain membership must not remove a local package
	}
	relative = filepath.ToSlash(relative)
	if root.Get("workspace") == nil || cargoWorkspaceMatches(root.Get("workspace.exclude"), relative) || tree.Get("workspace") != nil {
		return false
	}
	if workspace, ok := tree.Get("package.workspace").(string); ok {
		return path.Join(path.Dir(location.RealPath), workspace, "Cargo.toml") == rootLocation.RealPath
	}
	if cargoWorkspaceMember(root, relative) {
		return true
	}
	if relative == ".." || strings.HasPrefix(relative, "../") {
		return false
	}
	// Path dependencies within the workspace are implicit members, unless
	// another workspace root between the dependency and this root owns them.
	for dir := path.Dir(path.Dir(location.RealPath)); dir != rootDir; dir = path.Dir(dir) {
		if parent := resolver.RelativeFileByPath(location, path.Join(dir, "Cargo.toml")); parent != nil {
			manifest, err := readCargoManifest(resolver, *parent)
			if err != nil {
				return true
			}
			if manifest.Get("workspace") != nil {
				return false
			}
			if workspace, ok := manifest.Get("package.workspace").(string); ok {
				return path.Join(dir, workspace, "Cargo.toml") == rootLocation.RealPath
			}
		}
	}
	return true
}

func cargoDependencyTables(tree *toml.Tree) []*toml.Tree {
	tables := []*toml.Tree{tree}
	if targets, ok := tree.Get("target").(*toml.Tree); ok {
		for _, target := range targets.Keys() {
			if table, ok := targets.GetPath([]string{target}).(*toml.Tree); ok {
				tables = append(tables, table)
			}
		}
	}
	return tables
}

// Only remove packages reachable exclusively through development edges. Seed
// the production walk with workspace roots, unknown local packages, and anything
// not reached through a development edge, so incomplete evidence cannot remove
// unrelated packages or dependencies shared with another project member.
func excludeCargoDevDependencies(pkgs []pkg.Package, manifests map[string]*toml.Tree, roots map[string]bool) []pkg.Package {
	graph := newCargoDependencyGraph(pkgs, manifests)
	devReachable := graph.walk(graph.devSeeds, true)
	var seeds []int
	for i, p := range pkgs {
		key := p.Name + " " + p.Version
		unknownLocal := p.Metadata.(pkg.RustCargoLockEntry).Source == "" && manifests[key] == nil
		if !devReachable[i] || roots[key] || unknownLocal {
			seeds = append(seeds, i)
		}
	}
	return graph.filter(pkgs, graph.walk(seeds, false))
}

type cargoDependencyGraph struct {
	providers map[string][]int
	edges     map[int][]int
	devEdges  map[int]map[string]bool
	devSeeds  []int
}

func newCargoDependencyGraph(pkgs []pkg.Package, manifests map[string]*toml.Tree) cargoDependencyGraph {
	graph := cargoDependencyGraph{
		providers: make(map[string][]int),
		edges:     make(map[int][]int),
		devEdges:  make(map[int]map[string]bool),
	}
	scopes := make(map[int]cargoDependencyScopes)
	for i, p := range pkgs {
		for _, name := range dependencySpecification(p).Provides {
			graph.providers[name] = append(graph.providers[name], i)
		}
		if p.Metadata.(pkg.RustCargoLockEntry).Source == "" {
			if tree := manifests[p.Name+" "+p.Version]; tree != nil {
				scopes[i] = newCargoDependencyScopes(tree)
			}
		}
	}
	for i, p := range pkgs {
		graph.devEdges[i] = make(map[string]bool)
		for _, required := range dependencySpecification(p).Requires {
			if scopes[i].devOnlyEdge(graph.providers[required], pkgs) {
				graph.devEdges[i][required] = true
				graph.devSeeds = append(graph.devSeeds, graph.providers[required]...)
			} else {
				graph.edges[i] = append(graph.edges[i], graph.providers[required]...)
			}
		}
	}
	return graph
}

func (g cargoDependencyGraph) walk(seeds []int, includeDev bool) map[int]bool {
	seen := make(map[int]bool)
	for len(seeds) > 0 {
		i := seeds[len(seeds)-1]
		seeds = seeds[:len(seeds)-1]
		if seen[i] {
			continue
		}
		seen[i] = true
		seeds = append(seeds, g.edges[i]...)
		if includeDev {
			for required := range g.devEdges[i] {
				seeds = append(seeds, g.providers[required]...)
			}
		}
	}
	return seen
}

func (g cargoDependencyGraph) filter(pkgs []pkg.Package, retained map[int]bool) []pkg.Package {
	var result []pkg.Package
	for i, p := range pkgs {
		if !retained[i] {
			continue
		}
		metadata := p.Metadata.(pkg.RustCargoLockEntry)
		requires := make([]string, 0, len(metadata.Dependencies))
		for _, required := range metadata.Dependencies {
			if !g.devEdges[i][required] {
				requires = append(requires, required)
			}
		}
		metadata.Dependencies = requires
		p.Metadata = metadata
		p.SetID()
		result = append(result, p)
	}
	return result
}
