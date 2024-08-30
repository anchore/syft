package cpp

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

var _ generic.Parser = parseConanLock

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
	Version      string `json:"version"`
	ProfileHost  string `json:"profile_host"`
	ProfileBuild string `json:"profile_build,omitempty"`
	// conan v0.5+ lockfiles use "requires", "build_requires" and "python_requires"
	Requires       []string `json:"requires,omitempty"`
	BuildRequires  []string `json:"build_requires,omitempty"`
	PythonRequires []string `json:"python_requires,omitempty"`
}

// parseConanLock is a parser function for conan.lock (v1 and V2) contents, returning all packages discovered.
func parseConanLock(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var cl conanLock
	if err := json.NewDecoder(reader).Decode(&cl); err != nil {
		return nil, nil, err
	}

	// requires is a list of package indices. We first need to fill it, and then we can resolve the package
	// in a second iteration
	var indexToPkgMap = map[string]pkg.Package{}

	v1Pkgs := handleConanLockV2(cl, reader, indexToPkgMap)

	// we do not want to store the index list requires in the conan metadata, because it is not useful to have it in
	// the SBOM. Instead, we will store it in a map and then use it to build the relationships
	// maps pkg.ID to a list of indices
	var parsedPkgRequires = map[artifact.ID][]string{}

	v2Pkgs := handleConanLockV1(cl, reader, parsedPkgRequires, indexToPkgMap)

	var relationships []artifact.Relationship
	var pkgs []pkg.Package
	pkgs = append(pkgs, v1Pkgs...)
	pkgs = append(pkgs, v2Pkgs...)

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

	return pkgs, relationships, unknown.IfEmptyf(pkgs, "unable to determine packages")
}

// handleConanLockV1 handles the parsing of conan lock v1 files (aka v0.4)
func handleConanLockV1(cl conanLock, reader file.LocationReadCloser, parsedPkgRequires map[artifact.ID][]string, indexToPkgMap map[string]pkg.Package) []pkg.Package {
	var pkgs []pkg.Package
	for idx, node := range cl.GraphLock.Nodes {
		metadata := pkg.ConanV1LockEntry{
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
	return pkgs
}

// handleConanLockV2 handles the parsing of conan lock v2 files (aka v0.5)
func handleConanLockV2(cl conanLock, reader file.LocationReadCloser, indexToPkgMap map[string]pkg.Package) []pkg.Package {
	var pkgs []pkg.Package
	for _, ref := range cl.Requires {
		reference, name := parseConanV2Reference(ref)
		if name == "" {
			continue
		}

		p := newConanReferencePackage(
			reference,
			reader.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		)

		if p != nil {
			pk := *p
			pkgs = append(pkgs, pk)
			indexToPkgMap[name] = pk
		}
	}
	return pkgs
}

func parseOptions(options string) []pkg.KeyValue {
	o := make([]pkg.KeyValue, 0)
	if len(options) == 0 {
		return nil
	}

	kvps := strings.Split(options, "\n")
	for _, kvp := range kvps {
		kv := strings.Split(kvp, "=")
		if len(kv) == 2 {
			o = append(o, pkg.KeyValue{
				Key:   kv[0],
				Value: kv[1],
			})
		}
	}

	return o
}

func parseConanV2Reference(ref string) (pkg.ConanV2LockEntry, string) {
	// very flexible format name/version[@username[/channel]][#rrev][:pkgid[#prev]][%timestamp]
	reference := pkg.ConanV2LockEntry{Ref: ref}

	parts := strings.SplitN(ref, "%", 2)
	if len(parts) == 2 {
		ref = parts[0]
		reference.TimeStamp = parts[1]
	}

	parts = strings.SplitN(ref, ":", 2)
	if len(parts) == 2 {
		ref = parts[0]
		parts = strings.SplitN(parts[1], "#", 2)
		reference.PackageID = parts[0]
		if len(parts) == 2 {
			reference.PackageRevision = parts[1]
		}
	}

	parts = strings.SplitN(ref, "#", 2)
	if len(parts) == 2 {
		ref = parts[0]
		reference.RecipeRevision = parts[1]
	}

	parts = strings.SplitN(ref, "@", 2)
	if len(parts) == 2 {
		ref = parts[0]
		UsernameChannel := parts[1]

		parts = strings.SplitN(UsernameChannel, "/", 2)
		reference.Username = parts[0]
		if len(parts) == 2 {
			reference.Channel = parts[1]
		}
	}

	parts = strings.SplitN(ref, "/", 2)
	var name string
	if len(parts) == 2 {
		name = parts[0]
	} else {
		// consumer conanfile.txt or conanfile.py might not have a name
		name = ""
	}

	return reference, name
}
