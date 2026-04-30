package julia

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"

	"github.com/pelletier/go-toml"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
)

// this exists for parsing the file as-is
type manifestFile struct {
	JuliaVersion   string                   `toml:"julia_version"`
	ManifestFormat string                   `toml:"manifest_format"`
	Deps           map[string][]manifestDep `toml:"deps"`
}

// this exists for parsing the file as-is
type manifestDep struct {
	UUID     string `toml:"uuid"`
	Version  string `toml:"version"`
	Deps     any    `toml:"deps"` // this could be an array or an inline table
	Path     string `toml:"path"`
	WeakDeps any    `toml:"weakdeps"`
}

// this exists for parsing the file as-is
type projectFile struct {
	Location file.Location
	Deps     map[string]string   `toml:"deps"`
	Extras   map[string]string   `toml:"extras"`
	WeakDeps map[string]string   `toml:"weakdeps"`
	Targets  map[string][]string `toml:"targets"`
}

type manifestParser struct {
	cfg CatalogerConfig
}

type dependencyResource struct {
	ProjectDir string `json:"projectDir"`
	Resource   string `json:"resource"`
}

// this is used for processing after the manifest is parsed
type depEntry struct {
	name     string
	version  string
	uuid     string
	deps     []string // inline tables get coerced to arrays
	path     string
	weakDeps map[string]string
}

// used to simplify dependency resolution
type manifestIndex struct {
	entries    []depEntry
	uuidToDeps map[string][]string
}

func newManifestParser(cfg CatalogerConfig) *manifestParser {
	return &manifestParser{cfg: cfg}
}

func (p *manifestParser) parseManifest(_ context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	tree, err := toml.LoadReader(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to load Manifest.toml for parsing: %w", err)
	}

	m := parseManifestFile(tree)

	proj, err := parseProjectFile(resolver, reader)
	if err != nil {
		log.Tracef("unable to parse Project.toml: %v", err)
	}

	idx := p.buildIndex(m)
	pkgsToKinds := p.analyzePackages(idx, proj)
	pkgs := p.createPackages(idx, pkgsToKinds, proj, reader)

	return pkgs, dependency.Resolve(juliaManifestDependencySpecifier, pkgs), unknown.IfEmptyf(pkgs, "unable to determine packages")
}

func parseProjectFile(resolver file.Resolver, reader file.LocationReadCloser) (*projectFile, error) {
	if resolver == nil {
		return nil, fmt.Errorf("no resolver provided")
	}

	projectPath := filepath.Join(filepath.Dir(reader.RealPath), "Project.toml")

	projectLocation := resolver.RelativeFileByPath(reader.Location, projectPath)
	if projectLocation == nil {
		return nil, fmt.Errorf("unable to resolve: %s", projectPath)
	}

	contents, err := resolver.FileContentsByLocation(*projectLocation)
	if err != nil {
		return nil, err
	}
	defer internal.CloseAndLogError(contents, projectLocation.AccessPath)

	tree, err := toml.LoadReader(contents)
	if err != nil {
		return nil, fmt.Errorf("unable to load Project.toml: %w", err)
	}

	proj := projectFile{}
	if err = tree.Unmarshal(&proj); err != nil {
		return nil, fmt.Errorf("unable to parse Project.toml: %w", err)
	}
	proj.Location = projectLocation.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)

	return &proj, nil
}

func parseManifestFile(tree *toml.Tree) manifestFile {
	raw := tree.ToMap()

	if deps, ok := raw["deps"].(map[string]any); ok {
		return manifestFile{Deps: parseManifestDeps(deps)}
	}

	return manifestFile{Deps: parseManifestDeps(raw)}
}

func parseManifestDeps(raw map[string]any) map[string][]manifestDep {
	deps := make(map[string][]manifestDep)

	for name, value := range raw {
		switch name {
		case "julia_version", "manifest_format", "project_hash":
			continue
		}

		entries := parseManifestDepEntries(value)
		if len(entries) > 0 {
			deps[name] = entries
		}
	}

	return deps
}

func parseManifestDepEntries(value any) []manifestDep {
	switch entries := value.(type) {
	case []any:
		deps := make([]manifestDep, 0, len(entries))
		for _, entry := range entries {
			if m, ok := entry.(map[string]any); ok {
				deps = append(deps, parseManifestDepEntry(m))
			}
		}
		return deps
	case map[string]any:
		return []manifestDep{parseManifestDepEntry(entries)}
	default:
		return nil
	}
}

func parseManifestDepEntry(raw map[string]any) manifestDep {
	return manifestDep{
		UUID:     stringValue(raw["uuid"]),
		Version:  stringValue(raw["version"]),
		Deps:     raw["deps"],
		Path:     stringValue(raw["path"]),
		WeakDeps: raw["weakdeps"],
	}
}

func stringValue(value any) string {
	if s, ok := value.(string); ok {
		return s
	}
	return ""
}

// Coerce the multiple Julia package dependency formats into a map of UUIDs to dependencies
func (p *manifestParser) buildIndex(m manifestFile) manifestIndex {
	names := make([]string, 0, len(m.Deps))
	for name := range m.Deps {
		names = append(names, name)
	}
	sort.Strings(names)

	nameToUUID := make(map[string]string)
	existingUUID := make(map[string]struct{})
	for name, deps := range m.Deps {
		for _, dep := range deps {
			nameToUUID[name] = dep.UUID
			existingUUID[dep.UUID] = struct{}{}
		}
	}

	var entries []depEntry
	uuidToDeps := make(map[string][]string)

	for _, name := range names {
		for _, dep := range m.Deps[name] {
			depUUIDs := extractDeps(dep.Deps, nameToUUID, existingUUID)
			weakDeps := extractWeakDeps(dep.WeakDeps, nameToUUID)
			uuidToDeps[dep.UUID] = depUUIDs

			entries = append(entries, depEntry{
				name:     name,
				version:  dep.Version,
				uuid:     dep.UUID,
				deps:     depUUIDs,
				path:     dep.Path,
				weakDeps: weakDeps,
			})
		}
	}

	return manifestIndex{entries: entries, uuidToDeps: uuidToDeps}
}

// Determine what packages are reachable from the project (or manifest if there is no project) and set its dep kind
func (p *manifestParser) analyzePackages(idx manifestIndex, proj *projectFile) map[string]string {
	pkgsToKinds := make(map[string]string)

	var visitWithKind func(uuid, kind string)
	visitWithKind = func(uuid, kind string) {
		pkgsToKinds[uuid] = kind
		for _, depUUID := range idx.uuidToDeps[uuid] {
			visitWithKind(depUUID, kind)
		}
	}

	testExtras := make(map[string]struct{})
	if proj != nil {
		if testTarget, ok := proj.Targets["test"]; ok {
			for _, name := range testTarget {
				testExtras[name] = struct{}{}
			}
		}

		if p.cfg.IncludeWeakDeps {
			for _, uuid := range proj.WeakDeps {
				visitWithKind(uuid, optionalKind)
			}
		}

		if p.cfg.IncludeExtras {
			for name, uuid := range proj.Extras {
				if _, isTest := testExtras[name]; isTest {
					visitWithKind(uuid, testKind)
				} else {
					visitWithKind(uuid, optionalKind)
				}
			}
		}

		for _, uuid := range proj.Deps {
			visitWithKind(uuid, runtimeKind)
		}
	} else {
		// without a project we don't know what deps might be for extras, etc. so assume they are all runtime
		for _, e := range idx.entries {
			visitWithKind(e.uuid, runtimeKind)
		}
	}

	if p.cfg.IncludeWeakDeps {
		for _, e := range idx.entries {
			if _, isReachable := pkgsToKinds[e.uuid]; !isReachable {
				continue
			}
			for _, uuid := range e.weakDeps {
				if _, seen := pkgsToKinds[uuid]; !seen {
					pkgsToKinds[uuid] = optionalKind
				}
			}
		}
	}

	return pkgsToKinds
}

// Walk through everything reachable from the project (or manifest if there was no project) and create the final syft Packages
func (p *manifestParser) createPackages(idx manifestIndex, pkgsToKinds map[string]string, proj *projectFile, reader file.LocationReadCloser) []pkg.Package {
	var pkgs []pkg.Package
	loc := reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)
	seenTransitiveWeakDeps := make(map[string]struct{})

	entryUUIDs := make(map[string]struct{}, len(idx.entries))
	for _, e := range idx.entries {
		entryUUIDs[e.uuid] = struct{}{}
	}

	for _, e := range idx.entries {
		if _, ok := pkgsToKinds[e.uuid]; !ok {
			continue
		}

		deps := e.deps
		if p.cfg.IncludeWeakDeps && len(e.weakDeps) > 0 {
			deps = mergeStrings(deps, sortedValues(e.weakDeps))
		}

		entry := pkg.JuliaManifestEntry{
			UUID:           e.uuid,
			Deps:           deps,
			Path:           e.path,
			DependencyKind: pkgsToKinds[e.uuid],
		}
		pkgs = append(pkgs, newJuliaPackage(e.name, e.version, entry, loc))

		if p.cfg.IncludeWeakDeps {
			for name, uuid := range e.weakDeps {
				if _, exists := seenTransitiveWeakDeps[uuid]; exists {
					continue
				}
				if _, exists := entryUUIDs[uuid]; exists {
					continue
				}
				if _, ok := pkgsToKinds[uuid]; !ok {
					continue
				}
				seenTransitiveWeakDeps[uuid] = struct{}{}
				wdEntry := pkg.JuliaManifestEntry{
					UUID:           uuid,
					DependencyKind: pkgsToKinds[uuid],
				}
				pkgs = append(pkgs, newJuliaPackage(name, "", wdEntry, loc))
			}
		}
	}

	if proj != nil {
		pkgs = append(pkgs, p.createMissingProjectPackages(proj, pkgsToKinds, entryUUIDs)...)
	}

	return pkgs
}

// extras and weakdeps might not exist in any manifest. If we were asked to include them anyway, we need to generate
// partial package entries for them using whatever information we have (basically name and UUID).
func (p *manifestParser) createMissingProjectPackages(proj *projectFile, pkgsToKinds map[string]string, entryUUIDs map[string]struct{}) []pkg.Package {
	seen := make(map[string]struct{})
	testExtras := make(map[string]struct{})
	for _, name := range proj.Targets["test"] {
		testExtras[name] = struct{}{}
	}

	var pkgs []pkg.Package
	if p.cfg.IncludeExtras {
		for name, uuid := range proj.Extras {
			if _, exists := entryUUIDs[uuid]; exists {
				continue
			}
			if _, exists := seen[uuid]; exists {
				continue
			}
			seen[uuid] = struct{}{}
			kind := optionalKind
			if _, ok := testExtras[name]; ok {
				kind = testKind
			}
			pkgs = append(pkgs, newJuliaPackage(name, "", pkg.JuliaManifestEntry{
				UUID:           uuid,
				DependencyKind: kind,
			}, proj.Location))
		}
	}

	if p.cfg.IncludeWeakDeps {
		for name, uuid := range proj.WeakDeps {
			if _, exists := entryUUIDs[uuid]; exists {
				continue
			}
			if _, exists := seen[uuid]; exists {
				continue
			}
			if _, ok := pkgsToKinds[uuid]; !ok {
				continue
			}
			seen[uuid] = struct{}{}
			pkgs = append(pkgs, newJuliaPackage(name, "", pkg.JuliaManifestEntry{
				UUID:           uuid,
				DependencyKind: pkgsToKinds[uuid],
			}, proj.Location))
		}
	}

	return pkgs
}

func sortedValues(m map[string]string) []string {
	vals := make([]string, 0, len(m))
	for _, v := range m {
		vals = append(vals, v)
	}
	sort.Strings(vals)
	return vals
}

// weakdeps can be an array of package names in early manifest formats, or an inline table of package name to UUID
func extractWeakDeps(deps any, nameToUUID map[string]string) map[string]string {
	out := make(map[string]string)

	switch d := deps.(type) {
	case map[string]any:
		for name, v := range d {
			if uuid, ok := v.(string); ok {
				out[name] = uuid
			}
		}
	case []any:
		for _, v := range d {
			name, ok := v.(string)
			if !ok {
				continue
			}
			if uuid, ok := nameToUUID[name]; ok {
				out[name] = uuid
			}
		}
	}

	if len(out) == 0 {
		return nil
	}
	return out
}

// extractDeps handles the different TOML formats Julia uses for dependencies.
// deps can either be an array (names) or an inline table (uuids)
// Returns an array of UUIDs
func extractDeps(deps any, nameToUUID map[string]string, existingUUID map[string]struct{}) []string {
	if deps == nil {
		return nil
	}

	var depNamesAndUuids []string
	switch d := deps.(type) {
	// array of package names
	case []any:
		var result []string
		for _, v := range d {
			if s, ok := v.(string); ok {
				result = append(result, s)
			}
		}
		sort.Strings(result)
		depNamesAndUuids = result
	// inline table of package name to UUID
	case map[string]any:
		var result []string
		for _, v := range d {
			if uuid, ok := v.(string); ok {
				result = append(result, uuid)
			}
		}
		sort.Strings(result)
		depNamesAndUuids = result
	}

	var uuids []string
	for _, d := range depNamesAndUuids {
		if _, isUUID := existingUUID[d]; isUUID {
			uuids = append(uuids, d)
		} else if uuid, ok := nameToUUID[d]; ok {
			uuids = append(uuids, uuid)
		}
	}
	return uuids
}

func juliaManifestDependencySpecifier(p pkg.Package) dependency.Specification {
	meta, ok := p.Metadata.(pkg.JuliaManifestEntry)
	if !ok {
		log.Tracef("cataloger failed to extract Julia manifest metadata for package %+v", p.Name)
		return dependency.Specification{}
	}

	projectDir := packageProjectDir(p)
	provides := []string{scopedJuliaDependencyResource(projectDir, p.Name)}
	if meta.UUID != "" {
		provides = append(provides, scopedJuliaDependencyResource(projectDir, meta.UUID))
	}
	requires := make([]string, 0, len(meta.Deps))
	for _, dep := range meta.Deps {
		requires = append(requires, scopedJuliaDependencyResource(projectDir, dep))
	}

	return dependency.Specification{
		ProvidesRequires: dependency.ProvidesRequires{
			Provides: provides,
			Requires: requires,
		},
	}
}

// Each dep must be scoped to the project in which it is used. The same dep may appear in multiple nested projects,
// but Julia does not merge projects.
// This is used to fix dependency resolution when multiple projects are in the same SBOM.
func scopedJuliaDependencyResource(projectDir, resource string) string {
	encoded, _ := json.Marshal(dependencyResource{
		ProjectDir: projectDir,
		Resource:   resource,
	})
	return string(encoded)
}
