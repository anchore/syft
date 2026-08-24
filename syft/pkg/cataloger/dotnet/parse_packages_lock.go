package dotnet

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sort"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/relationship"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

var _ generic.Parser = parseDotnetPackagesLock

// dotnetPackagesLockTypePrecedence ranks dependency types so that when the same
// package+version appears under more than one target framework with different
// types, the entry describing the strongest relationship to the project wins
// deterministically (e.g. a package referenced directly by the project under
// one framework but pulled transitively under another is reported as Direct).
var dotnetPackagesLockTypePrecedence = []string{
	"Direct",
	"Project",
	"CentralTransitive",
	"Transitive",
}

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

	// collect all deps here. Iterate target frameworks in sorted order and
	// merge entries deterministically: the same package+version can appear
	// under multiple target frameworks with different dependency types (e.g.
	// Direct under net8.0 but Transitive under netstandard2.0), and Go map
	// iteration order is randomized -- without sorting/merging, which entry
	// wins (and thus the reported metadata) changes between runs (see #5211).
	allDependencies := make(map[string]dotnetPackagesLockDep)

	tfms := make([]string, 0, len(lockFile.Dependencies))
	for tfm := range lockFile.Dependencies {
		tfms = append(tfms, tfm)
	}
	sort.Strings(tfms)

	var names []string
	for _, tfm := range tfms {
		dependencies := lockFile.Dependencies[tfm]

		namesForTfm := make([]string, 0, len(dependencies))
		for name := range dependencies {
			namesForTfm = append(namesForTfm, name)
		}
		sort.Strings(namesForTfm)

		for _, name := range namesForTfm {
			dep := dependencies[name]
			depNameVersion := createNameAndVersion(name, dep.Resolved)

			if existing, ok := allDependencies[depNameVersion]; ok {
				mergeDotnetPackagesLockDep(&existing, dep)
				allDependencies[depNameVersion] = existing
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

	// fill up relationships
	for depNameVersion, dep := range allDependencies {
		parentPkg, ok := pkgMap[depNameVersion]
		if !ok {
			log.Debugf("package \"%s\" not found in map of all packages", depNameVersion)
			continue
		}

		for childDepName, childDepVersion := range dep.Dependencies {
			childDepNameVersion := createNameAndVersion(childDepName, childDepVersion)

			// try and find pkg for dependency with exact name and version
			childPkg, ok := pkgMap[childDepNameVersion]
			if !ok {
				// no exact match found, lets match on name only, lockfile will contain other version of pkg
				cpkg, ok := findPkgByName(childDepName, pkgMap)
				if !ok {
					log.Debugf("dependency \"%s\" of package \"%s\" not found in map of all packages", childDepNameVersion, depNameVersion)
					continue
				}

				childPkg = *cpkg
			}

			rel := artifact.Relationship{
				From: childPkg,
				To:   parentPkg,
				Type: artifact.DependencyOfRelationship,
			}
			relationships = append(relationships, rel)
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

// mergeDotnetPackagesLockDep folds a second target-framework entry for the
// same package+version into the first one deterministically: the dependency
// type with the highest precedence wins (ties keep the incumbent), and any
// field still empty on the merged entry is filled from the new one.
func mergeDotnetPackagesLockDep(dst *dotnetPackagesLockDep, other dotnetPackagesLockDep) {
	if dotnetPackagesLockTypeRank(other.Type) < dotnetPackagesLockTypeRank(dst.Type) {
		dst.Type = other.Type
	}
	if dst.ContentHash == "" {
		dst.ContentHash = other.ContentHash
	}
	for name, version := range other.Dependencies {
		if dst.Dependencies == nil {
			dst.Dependencies = make(map[string]string)
		}
		if _, ok := dst.Dependencies[name]; !ok {
			dst.Dependencies[name] = version
		}
	}
}

func dotnetPackagesLockTypeRank(typ string) int {
	if i := slices.Index(dotnetPackagesLockTypePrecedence, typ); i >= 0 {
		return i
	}
	return len(dotnetPackagesLockTypePrecedence)
}

func findPkgByName(pkgName string, pkgMap map[string]pkg.Package) (*pkg.Package, bool) {
	for pkgNameVersion, pkg := range pkgMap {
		name, _ := extractNameAndVersion(pkgNameVersion)
		if name == pkgName {
			return &pkg, true
		}
	}

	return nil, false
}
