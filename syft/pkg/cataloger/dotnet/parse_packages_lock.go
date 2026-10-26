package dotnet

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/relationship"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

var _ generic.Parser = parseDotnetPackagesLock

var packagesLockTypePrecedence = []string{"Project", "Direct", "CentralTransitive", "Transitive"}

type dotnetPackagesLock struct {
	Version      int                                         `json:"version"`
	Dependencies map[string]map[string]dotnetPackagesLockDep `json:"dependencies"`
}

type dotnetPackagesLockDep struct {
	Type         string            `json:"type"`
	Requested    string            `json:"requested"`
	Resolved     string            `json:"resolved"`
	ContentHash  string            `json:"contentHash"`
	Dependencies map[string]string `json:"dependencies,omitempty"`
}

type packagesLockEntry struct {
	name string
	dep  dotnetPackagesLockDep
}

func (e packagesLockEntry) nameVersion() string {
	return createNameAndVersion(e.name, e.dep.Resolved)
}

// key identifies the package an entry describes. NuGet package IDs are case-insensitive, so two spellings of the
// same ID and version are one package.
func (e packagesLockEntry) key() string {
	return createNameAndVersion(strings.ToLower(e.name), e.dep.Resolved)
}

type packagesLockFramework struct {
	name    string
	entries []packagesLockEntry
	// byName is keyed by the lowercased package name, since NuGet package IDs are case-insensitive.
	byName map[string]packagesLockEntry
}

func (f packagesLockFramework) find(name string) (packagesLockEntry, bool) {
	e, ok := f.byName[strings.ToLower(name)]
	return e, ok
}

type packagesLockEdge struct {
	child, parent artifact.ID
}

func parseDotnetPackagesLock(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	dec := json.NewDecoder(reader)

	// unmarshal file
	var lockFile dotnetPackagesLock
	if err := dec.Decode(&lockFile); err != nil {
		return nil, nil, fmt.Errorf("failed to parse packages.lock.json file: %w", err)
	}

	frameworks := newPackagesLockFrameworks(lockFile)

	// create artifact for each pkg
	var pkgs []pkg.Package
	pkgMap := make(map[string]pkg.Package)

	for _, entry := range mergePackagesLockEntries(frameworks) {
		dotnetPkg := newDotnetPackagesLockPackage(entry.name, entry.dep, reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))
		if dotnetPkg != nil {
			pkgs = append(pkgs, *dotnetPkg)
			pkgMap[entry.key()] = *dotnetPkg
		}
	}

	relationships := packagesLockRelationships(frameworks, pkgMap)

	// sort the relationships for deterministic output
	relationship.Sort(relationships)

	return pkgs, relationships, nil
}

func newPackagesLockFrameworks(lockFile dotnetPackagesLock) []packagesLockFramework {
	var frameworks []packagesLockFramework

	for _, frameworkName := range slices.Sorted(maps.Keys(lockFile.Dependencies)) {
		deps := lockFile.Dependencies[frameworkName]
		framework := packagesLockFramework{
			name:   frameworkName,
			byName: make(map[string]packagesLockEntry, len(deps)),
		}

		for _, name := range slices.Sorted(maps.Keys(deps)) {
			entry := packagesLockEntry{name: name, dep: deps[name]}
			framework.entries = append(framework.entries, entry)
			framework.byName[strings.ToLower(name)] = entry
		}

		frameworks = append(frameworks, framework)
	}

	return frameworks
}

func mergePackagesLockEntries(frameworks []packagesLockFramework) []packagesLockEntry {
	merged := make(map[string]packagesLockEntry)

	for _, framework := range frameworks {
		for _, entry := range framework.entries {
			key := entry.key()
			if existing, ok := merged[key]; ok && !isMoreDirect(entry.dep.Type, existing.dep.Type) {
				continue
			}
			merged[key] = entry
		}
	}

	var entries []packagesLockEntry
	for _, key := range slices.Sorted(maps.Keys(merged)) {
		entries = append(entries, merged[key])
	}

	return entries
}

func isMoreDirect(a, b string) bool {
	rankA, rankB := packagesLockTypeRank(a), packagesLockTypeRank(b)
	if rankA != rankB {
		return rankA < rankB
	}
	return a < b
}

func packagesLockTypeRank(t string) int {
	if i := slices.Index(packagesLockTypePrecedence, t); i >= 0 {
		return i
	}
	return len(packagesLockTypePrecedence)
}

func packagesLockRelationships(frameworks []packagesLockFramework, pkgMap map[string]pkg.Package) []artifact.Relationship {
	var relationships []artifact.Relationship

	frameworksByName := make(map[string]packagesLockFramework, len(frameworks))
	for _, framework := range frameworks {
		frameworksByName[framework.name] = framework
	}

	seen := make(map[packagesLockEdge]struct{})
	for _, framework := range frameworks {
		base, hasBase := frameworksByName[baseFrameworkName(framework.name)]
		if !hasBase || base.name == framework.name {
			base = packagesLockFramework{}
		}

		for _, entry := range framework.entries {
			parentPkg, ok := pkgMap[entry.key()]
			if !ok {
				log.Debugf("package %q not found in map of all packages", entry.nameVersion())
				continue
			}

			relationships = append(relationships, packagesLockEntryRelationships(entry, parentPkg, framework, base, pkgMap, seen)...)
		}
	}

	return relationships
}

func packagesLockEntryRelationships(entry packagesLockEntry, parentPkg pkg.Package, framework, base packagesLockFramework, pkgMap map[string]pkg.Package, seen map[packagesLockEdge]struct{}) []artifact.Relationship {
	var relationships []artifact.Relationship

	for _, childName := range slices.Sorted(maps.Keys(entry.dep.Dependencies)) {
		child, ok := findPackagesLockDependency(childName, framework, base)
		if !ok {
			log.Debugf("dependency %q of package %q not found under target framework %q", childName, entry.nameVersion(), framework.name)
			continue
		}

		childPkg, ok := pkgMap[child.key()]
		if !ok {
			log.Debugf("package %q not found in map of all packages", child.nameVersion())
			continue
		}

		// a package listing itself (possibly under another casing) is not a dependency
		if childPkg.ID() == parentPkg.ID() {
			continue
		}

		key := packagesLockEdge{child: childPkg.ID(), parent: parentPkg.ID()}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}

		relationships = append(relationships, artifact.Relationship{
			From: childPkg,
			To:   parentPkg,
			Type: artifact.DependencyOfRelationship,
		})
	}

	return relationships
}

// findPackagesLockDependency finds the entry a dependency edge points at. The version on an edge is only the lower
// bound of a version range, so the edge resolves to whatever version its target framework resolved. Runtime-specific
// sections such as "net8.0/win-x64" may reference packages listed only in their base framework ("net8.0"). An edge
// that resolves nowhere is dropped rather than guessed from another target framework.
func findPackagesLockDependency(name string, framework, base packagesLockFramework) (packagesLockEntry, bool) {
	if entry, ok := framework.find(name); ok {
		return entry, true
	}
	return base.find(name)
}

// baseFrameworkName returns the target framework of a runtime-specific section, such as "net8.0" for "net8.0/win-x64".
func baseFrameworkName(frameworkName string) string {
	name, _, _ := strings.Cut(frameworkName, "/")
	return name
}

func newDotnetPackagesLockPackage(name string, dep dotnetPackagesLockDep, locations ...file.Location) *pkg.Package {
	metadata := pkg.DotnetPackagesLockEntry{
		Name:        name,
		Version:     dep.Resolved,
		ContentHash: dep.ContentHash,
		Type:        dep.Type,
	}

	p := &pkg.Package{
		Name:      name,
		Version:   dep.Resolved,
		Type:      pkg.DotnetPkg,
		Metadata:  metadata,
		Locations: file.NewLocationSet(locations...),
		Language:  pkg.Dotnet,
		PURL:      packagesLockPackageURL(name, dep.Resolved),
	}

	p.SetID()

	return p
}

func packagesLockPackageURL(name, version string) string {
	var qualifiers packageurl.Qualifiers

	return packageurl.NewPackageURL(
		packageurl.TypeNuget, // See explanation in syft/pkg/cataloger/dotnet/package.go as to why this was chosen.
		"",
		name,
		version,
		qualifiers,
		"",
	).ToString()
}
