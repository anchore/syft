package dotnet

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

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
			names = append(names, name)
			allDependencies[name] = dep
		}
	}

	// sort the names so that the order of the packages is deterministic
	sort.Strings(names)

	// create artifact for each pkg
	for _, name := range names {
		dep := allDependencies[name]
		dotnetPkg := newDotnetPackagesLockPackage(name, dep, reader.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))
		if dotnetPkg != nil {
			pkgs = append(pkgs, *dotnetPkg)
			pkgMap[name] = *dotnetPkg
		}
	}

	// fill up relationships
	for name, dep := range allDependencies {
		parentPkg, ok := pkgMap[name]
		if !ok {
			log.Debugf("unable to find package in map: %s", name)
			continue
		}

		for childName := range dep.Dependencies {
			childPkg, ok := pkgMap[childName]
			if !ok {
				log.Debugf("unable to find dependency package in map: %s", childName)
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
	metadata := pkg.DotnetDepsEntry{
		Name:    name,
		Version: dep.Resolved,
		Sha512:  dep.ContentHash,
	}

	return &pkg.Package{
		Name:      name,
		Version:   dep.Resolved,
		Type:      pkg.DotnetPkg,
		Metadata:  metadata,
		Locations: file.NewLocationSet(locations...),
		Language:  pkg.Dotnet,
		PURL:      packageURL(metadata),
	}
}
