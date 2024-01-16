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
	Version      string `json:"version"`
	ProfileHost  string `json:"profile_host"`
	ProfileBuild string `json:"profile_build,omitempty"`
	// conan v0.5+ lockfiles use "requires", "build_requires" and "python_requires"
	Requires       []string `json:"requires,omitempty"`
	BuildRequires  []string `json:"build_requires,omitempty"`
	PythonRequires []string `json:"python_requires,omitempty"`
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

	// Support for conan lock 2.x requires field
	for _, ref := range cl.Requires {
		reference := parseConanV2Reference(ref)
		if reference.Name == "" {
			continue
		}

		p := newConanRefrencePackage(
			reference,
			reader.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		)

		if p != nil {
			pk := *p
			pkgs = append(pkgs, pk)
			indexToPkgMap[reference.Name] = pk
		}

	}

	// we do not want to store the index list requires in the conan metadata, because it is not useful to have it in
	// the SBOM. Instead, we will store it in a map and then use it to build the relationships
	// maps pkg.ID to a list of indices
	var parsedPkgRequires = map[artifact.ID][]string{}

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

func parseConanV2Reference(ref string) pkg.ConanV2LockEntry {
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
	if len(parts) == 2 {
		reference.Name = parts[0]
		reference.Version = parts[1]
	} else {
		// consumer conanfile.txt or conanfile.py might not have a name
		reference.Name = ""
		reference.Version = ref
	}

	return reference
}
