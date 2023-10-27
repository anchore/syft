package cpp

import (
	"encoding/json"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

var _ generic.Parser = parseConanlock

type conanLock struct {
	GraphLock struct {
		Nodes map[string]struct {
			Ref            string   `json:"ref"`
			PackageID      string   `json:"package_id"`
			Context        string   `json:"context"`
			Prev           string   `json:"prev"`
			Requires       []string `json:"requires"`
			PythonRequires string   `json:"py_requires"`
			Options        string   `json:"options"`
			Path           string   `json:"path"`
		} `json:"nodes"`
	} `json:"graph_lock"`
	Version     string `json:"version"`
	ProfileHost string `json:"profile_host"`
}

// parseConanlock is a parser function for conan.lock contents, returning all packages discovered.
func parseConanlock(_ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var pkgs []pkg.Package
	var cl conanLock
	if err := json.NewDecoder(reader).Decode(&cl); err != nil {
		return nil, nil, err
	}

	// requires is a list of package indices. We first need to fill it, and then we can resolve the package
	// in a second iteration
	var indexToPkgMap = map[string]pkg.Package{}

	// we do not want to store the index list requires in the conan metadata, because it is not useful to have it in
	// the SBOM. Instead, we will store it in a map and then use it to build the relationships
	// maps pkg.ID to a list of indices
	var parsedPkgRequires = map[artifact.ID][]string{}

	for idx, node := range cl.GraphLock.Nodes {
		metadata := pkg.ConanLockEntry{
			Ref:       node.Ref,
			Options:   parseOptions(node.Options),
			Path:      node.Path,
			Context:   node.Context,
			PackageID: node.PackageID,
			Prev:      node.Prev,
		}

		p := newConanlockPackage(
			metadata,
			reader.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		)

		if p != nil {
			pk := *p
			pkgs = append(pkgs, pk)
			parsedPkgRequires[pk.ID()] = node.Requires
			indexToPkgMap[idx] = pk
		}
	}

	var relationships []artifact.Relationship

	for _, p := range pkgs {
		requires := parsedPkgRequires[p.ID()]
		for _, r := range requires {
			// this is a pkg that package "p" depends on... make a relationship
			relationships = append(relationships, artifact.Relationship{
				From: indexToPkgMap[r],
				To:   p,
				Type: artifact.DependencyOfRelationship,
			})
		}
	}

	return pkgs, relationships, nil
}

func parseOptions(options string) map[string]string {
	o := make(map[string]string)
	if len(options) == 0 {
		return nil
	}

	kvps := strings.Split(options, "\n")
	for _, kvp := range kvps {
		kv := strings.Split(kvp, "=")
		if len(kv) == 2 {
			o[kv[0]] = kv[1]
		}
	}

	return o
}
