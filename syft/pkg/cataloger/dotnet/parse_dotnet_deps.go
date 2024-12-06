package dotnet

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/relationship"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

var _ generic.Parser = parseDotnetDeps

type dotnetDeps struct {
	RuntimeTarget dotnetRuntimeTarget                    `json:"runtimeTarget"`
	Targets       map[string]map[string]dotnetDepsTarget `json:"targets"`
	Libraries     map[string]dotnetDepsLibrary           `json:"libraries"`
}

type dotnetRuntimeTarget struct {
	Name string `json:"name"`
}

type dotnetDepsTarget struct {
	Dependencies map[string]string   `json:"dependencies"`
	Runtime      map[string]struct{} `json:"runtime"`
}

type dotnetDepsLibrary struct {
	Type     string `json:"type"`
	Path     string `json:"path"`
	Sha512   string `json:"sha512"`
	HashPath string `json:"hashPath"`
}

//nolint:funlen
func parseDotnetDeps(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var pkgs []pkg.Package
	var pkgMap = make(map[string]pkg.Package)
	var relationships []artifact.Relationship

	dec := json.NewDecoder(reader)

	var depsDoc dotnetDeps
	if err := dec.Decode(&depsDoc); err != nil {
		return nil, nil, fmt.Errorf("failed to parse deps.json file: %w", err)
	}

	rootName := getDepsJSONFilePrefix(reader.Path())
	if rootName == "" {
		return nil, nil, fmt.Errorf("unable to determine root package name from deps.json file: %s", reader.Path())
	}
	var rootPkg *pkg.Package
	for nameVersion, lib := range depsDoc.Libraries {
		name, _ := extractNameAndVersion(nameVersion)
		if lib.Type == "project" && name == rootName {
			rootPkg = newDotnetDepsPackage(
				nameVersion,
				lib,
				reader.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
			)
		}
	}
	if rootPkg == nil {
		return nil, nil, fmt.Errorf("unable to determine root package from deps.json file: %s", reader.Path())
	}
	pkgs = append(pkgs, *rootPkg)
	pkgMap[createNameAndVersion(rootPkg.Name, rootPkg.Version)] = *rootPkg

	var names []string
	for nameVersion := range depsDoc.Libraries {
		names = append(names, nameVersion)
	}
	// sort the names so that the order of the packages is deterministic
	sort.Strings(names)

	for _, nameVersion := range names {
		// skip the root package
		name, version := extractNameAndVersion(nameVersion)
		if name == rootPkg.Name && version == rootPkg.Version {
			continue
		}

		lib := depsDoc.Libraries[nameVersion]
		dotnetPkg := newDotnetDepsPackage(
			nameVersion,
			lib,
			reader.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		)

		if dotnetPkg != nil {
			pkgs = append(pkgs, *dotnetPkg)
			pkgMap[nameVersion] = *dotnetPkg
		}
	}

	for pkgNameVersion, target := range depsDoc.Targets[depsDoc.RuntimeTarget.Name] {
		for depName, depVersion := range target.Dependencies {
			depNameVersion := createNameAndVersion(depName, depVersion)
			depPkg, ok := pkgMap[depNameVersion]
			if !ok {
				log.Debug("unable to find package in map", depNameVersion)
				continue
			}
			p, ok := pkgMap[pkgNameVersion]
			if !ok {
				log.Debug("unable to find package in map", pkgNameVersion)
				continue
			}
			rel := artifact.Relationship{
				From: depPkg,
				To:   p,
				Type: artifact.DependencyOfRelationship,
			}
			relationships = append(relationships, rel)
		}
	}

	// sort the relationships for deterministic output
	// TODO: ideally this would be replaced with artifact.SortRelationships when one exists and is type agnostic.
	// this will only consider package-to-package relationships.
	relationship.Sort(relationships)

	return pkgs, relationships, unknown.IfEmptyf(pkgs, "unable to determine packages")
}
