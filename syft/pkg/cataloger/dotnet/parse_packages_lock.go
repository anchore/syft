package dotnet

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"sort"

	"github.com/anchore/go-version"
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/relationship"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

var _ generic.Parser = parseDotnetPackagesLock

// directDependencyType is the "type" NuGet writes for a package the project references directly.
const directDependencyType = "Direct"

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

func parseDotnetPackagesLock(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	dec := json.NewDecoder(reader)

	// unmarshal file
	var lockFile dotnetPackagesLock
	if err := dec.Decode(&lockFile); err != nil {
		return nil, nil, fmt.Errorf("failed to parse packages.lock.json file: %w", err)
	}

	names, allDependencies := collectPackagesLockDeps(lockFile)

	// create artifact for each pkg
	var pkgs []pkg.Package
	pkgMap := make(map[string]pkg.Package)

	for _, nameVersion := range names {
		name, _ := extractNameAndVersion(nameVersion)

		dep := allDependencies[nameVersion]
		dotnetPkg := newDotnetPackagesLockPackage(name, dep, reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))
		if dotnetPkg != nil {
			pkgs = append(pkgs, *dotnetPkg)
			pkgMap[nameVersion] = *dotnetPkg
		}
	}

	relationships := packagesLockRelationships(lockFile, pkgMap)

	// sort the relationships for deterministic output
	relationship.Sort(relationships)

	return pkgs, relationships, nil
}

// collectPackagesLockDeps flattens the per-target-framework entries into one entry per name and version, returning
// the sorted keys alongside the entries so that package order is deterministic. A package may appear under several
// target frameworks, and "Direct" wins when it does: some target framework references the package directly.
func collectPackagesLockDeps(lockFile dotnetPackagesLock) ([]string, map[string]dotnetPackagesLockDep) {
	allDependencies := make(map[string]dotnetPackagesLockDep)

	var names []string
	for _, targetFramework := range slices.Sorted(maps.Keys(lockFile.Dependencies)) {
		for _, name := range slices.Sorted(maps.Keys(lockFile.Dependencies[targetFramework])) {
			dep := lockFile.Dependencies[targetFramework][name]
			depNameVersion := createNameAndVersion(name, dep.Resolved)

			if existing, ok := allDependencies[depNameVersion]; ok {
				if existing.Type != directDependencyType && dep.Type == directDependencyType {
					allDependencies[depNameVersion] = dep
				}
				continue
			}

			names = append(names, depNameVersion)
			allDependencies[depNameVersion] = dep
		}
	}

	// sort the names so that the order of the packages is deterministic
	sort.Strings(names)

	return names, allDependencies
}

// packagesLockRelationships resolves each dependency within its own target framework so that lockfiles pinning
// multiple versions of the same package resolve to the correct one.
func packagesLockRelationships(lockFile dotnetPackagesLock, pkgMap map[string]pkg.Package) []artifact.Relationship {
	var relationships []artifact.Relationship

	seen := make(map[string]struct{})
	for _, targetFramework := range slices.Sorted(maps.Keys(lockFile.Dependencies)) {
		frameworkDeps := lockFile.Dependencies[targetFramework]

		for _, name := range slices.Sorted(maps.Keys(frameworkDeps)) {
			dep := frameworkDeps[name]
			depNameVersion := createNameAndVersion(name, dep.Resolved)

			parentPkg, ok := pkgMap[depNameVersion]
			if !ok {
				log.Debugf("package \"%s\" not found in map of all packages", depNameVersion)
				continue
			}

			relationships = append(relationships, packagesLockDepRelationships(dep, parentPkg, depNameVersion, frameworkDeps, pkgMap, seen)...)
		}
	}

	return relationships
}

// packagesLockDepRelationships returns the edges declared by a single package under one target framework, skipping
// any edge already recorded in seen -- frameworks that resolve to the same versions would otherwise repeat it.
func packagesLockDepRelationships(dep dotnetPackagesLockDep, parentPkg pkg.Package, depNameVersion string, frameworkDeps map[string]dotnetPackagesLockDep, pkgMap map[string]pkg.Package, seen map[string]struct{}) []artifact.Relationship {
	var relationships []artifact.Relationship

	for _, childDepName := range slices.Sorted(maps.Keys(dep.Dependencies)) {
		childDepVersion := dep.Dependencies[childDepName]

		childPkg, ok := findDependencyPkg(childDepName, childDepVersion, frameworkDeps, pkgMap)
		if !ok {
			log.Debugf("dependency \"%s\" of package \"%s\" not found in map of all packages", createNameAndVersion(childDepName, childDepVersion), depNameVersion)
			continue
		}

		key := string(childPkg.ID()) + string(parentPkg.ID())
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}

		relationships = append(relationships, artifact.Relationship{
			From: *childPkg,
			To:   parentPkg,
			Type: artifact.DependencyOfRelationship,
		})
	}

	return relationships
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

// findDependencyPkg finds the package a dependency points at. The version of a dependency edge is the lower bound
// of a version range, not a pin, so prefer whatever version this target framework actually resolved to.
func findDependencyPkg(name, declaredVersion string, frameworkDeps map[string]dotnetPackagesLockDep, pkgMap map[string]pkg.Package) (*pkg.Package, bool) {
	if dep, ok := frameworkDeps[name]; ok {
		if p, ok := pkgMap[createNameAndVersion(name, dep.Resolved)]; ok {
			return &p, true
		}
	}

	if p, ok := pkgMap[createNameAndVersion(name, declaredVersion)]; ok {
		return &p, true
	}

	return findPkgByName(name, pkgMap)
}

// findPkgByName returns the lowest-versioned package with the given name. This is a last-resort fallback for
// lockfiles where a dependency edge names a package that is absent from its own target framework
func findPkgByName(pkgName string, pkgMap map[string]pkg.Package) (*pkg.Package, bool) {
	var candidates []string
	for pkgNameVersion := range pkgMap {
		name, _ := extractNameAndVersion(pkgNameVersion)
		if name == pkgName {
			candidates = append(candidates, pkgNameVersion)
		}
	}

	if len(candidates) == 0 {
		return nil, false
	}

	// versions that don't parse sort after those that do
	sort.Slice(candidates, func(i, j int) bool {
		_, vi := extractNameAndVersion(candidates[i])
		_, vj := extractNameAndVersion(candidates[j])

		si, erri := version.NewVersion(vi)
		sj, errj := version.NewVersion(vj)

		if (erri == nil) != (errj == nil) {
			return erri == nil
		}

		if erri == nil && !si.Equal(sj) {
			return si.LessThan(sj)
		}

		return candidates[i] < candidates[j]
	})

	p := pkgMap[candidates[0]]

	return &p, true
}
