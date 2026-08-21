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

func parseDotnetPackagesLock(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) { //nolint:funlen
	var pkgs []pkg.Package
	var pkgMap = make(map[string]pkg.Package)
	var relationships []artifact.Relationship

	dec := json.NewDecoder(reader)

	// unmarshal file
	var lockFile dotnetPackagesLock
	if err := dec.Decode(&lockFile); err != nil {
		return nil, nil, fmt.Errorf("failed to parse packages.lock.json file: %w", err)
	}

	// collect all deps here
	allDependencies := make(map[string]dotnetPackagesLockDep)

	var names []string
	for _, dependencies := range lockFile.Dependencies {
		for name, dep := range dependencies {
			depNameVersion := createNameAndVersion(name, dep.Resolved)

			if slices.Contains(names, depNameVersion) {
				continue
			}

			names = append(names, depNameVersion)
			allDependencies[depNameVersion] = dep
		}
	}

	// sort the names so that the order of the packages is deterministic
	sort.Strings(names)

	// create artifact for each pkg
	for _, nameVersion := range names {
		name, _ := extractNameAndVersion(nameVersion)

		dep := allDependencies[nameVersion]
		dotnetPkg := newDotnetPackagesLockPackage(name, dep, reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))
		if dotnetPkg != nil {
			pkgs = append(pkgs, *dotnetPkg)
			pkgMap[nameVersion] = *dotnetPkg
		}
	}

	// fill up relationships, resolving each dependency within its own target framework so that
	// lockfiles pinning multiple versions of the same package resolve to the correct one
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
		}
	}

	// sort the relationships for deterministic output
	relationship.Sort(relationships)

	return pkgs, relationships, nil
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

// findDependencyPkg resolves a declared dependency to a package, preferring the version resolved within the
// same target framework, since the declared version is only a lower bound and the same package may be resolved
// to different versions across target frameworks.
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

// findPkgByName returns the lowest-versioned package matching the given name, which is the version NuGet would
// select for a lower-bound requirement. Candidates are sorted so that the result is deterministic.
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

	sort.Slice(candidates, func(i, j int) bool {
		_, vi := extractNameAndVersion(candidates[i])
		_, vj := extractNameAndVersion(candidates[j])

		si, erri := version.NewVersion(vi)
		sj, errj := version.NewVersion(vj)
		if erri == nil && errj == nil && !si.Equal(sj) {
			return si.LessThan(sj)
		}

		return candidates[i] < candidates[j]
	})

	p := pkgMap[candidates[0]]

	return &p, true
}
