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
		dotnetPkg := newDotnetPackagesLockPackage(name, dep, reader.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))
		if dotnetPkg != nil {
			pkgs = append(pkgs, *dotnetPkg)
			pkgMap[nameVersion] = *dotnetPkg
		}
	}

	// fill up relationships
	for pkgNameVersion, dep := range allDependencies {
		parentPkg, ok := pkgMap[pkgNameVersion]
		if !ok {
			log.Debug("package \"%s\" not found in map of all pacakges", pkgNameVersion)
			continue
		}

		for childName, childVersion := range dep.Dependencies {
			childNameVersion := createNameAndVersion(childName, childVersion)

			childPkg, ok := pkgMap[childNameVersion]
			if !ok {
				log.Debug("dependency \"%s\" of package \"%s\" not found in map of all packages, it might be required in a different version", childNameVersion, pkgNameVersion)
				continue
			}

			rel := artifact.Relationship{
				From: parentPkg,
				To:   childPkg,
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

	return &pkg.Package{
		Name:      name,
		Version:   dep.Resolved,
		Type:      pkg.DotnetPkg,
		Metadata:  metadata,
		Locations: file.NewLocationSet(locations...),
		Language:  pkg.Dotnet,
		PURL:      packagesLockPackageURL(name, dep.Resolved),
	}
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
