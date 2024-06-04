package dependency

import (
	"sort"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// Specification holds strings that indicate abstract resources that a package provides for other packages and
// requires for itself. These strings can represent anything from file paths, package names, or any other concept
// that is useful for dependency resolution within that packing ecosystem.
type Specification struct {
	ProvidesRequires

	// Variants allows for specifying multiple sets of provides/requires for a single package. This is useful
	// in cases when you have conditional optional dependencies for a package.
	Variants []ProvidesRequires
}

type ProvidesRequires struct {
	// Provides holds a list of abstract resources that this package provides for other packages.
	Provides []string

	// Requires holds a list of abstract resources that this package requires from other packages.
	Requires []string
}

// Specifier is a function that takes a package and extracts a Specification, describing resources
// the package provides and needs.
type Specifier func(pkg.Package) Specification

// Processor returns a generic processor that will resolve relationships between packages based on the dependency claims.
func Processor(s Specifier) generic.Processor {
	return func(pkgs []pkg.Package, rels []artifact.Relationship, err error) ([]pkg.Package, []artifact.Relationship, error) {
		// we can't move forward unless all package IDs have been set
		for idx, p := range pkgs {
			id := p.ID()
			if id == "" {
				p.SetID()
				pkgs[idx] = p
			}
		}

		rels = append(rels, Resolve(s, pkgs)...)
		return pkgs, rels, err
	}
}

// Resolve will create relationships between packages based on the dependency claims of each package.
func Resolve(specifier Specifier, pkgs []pkg.Package) (relationships []artifact.Relationship) {
	pkgsProvidingResource := make(map[string]internal.Set[artifact.ID])

	pkgsByID := make(map[artifact.ID]pkg.Package)
	specsByPkg := make(map[artifact.ID][]ProvidesRequires)

	for _, p := range pkgs {
		id := p.ID()
		pkgsByID[id] = p
		specsByPkg[id] = allProvides(pkgsProvidingResource, id, specifier(p))
	}

	seen := strset.New()
	for _, dependantPkg := range pkgs {
		specs := specsByPkg[dependantPkg.ID()]
		for _, spec := range specs {
			for _, resource := range deduplicate(spec.Requires) {
				for providingPkgID := range pkgsProvidingResource[resource] {
					// prevent creating duplicate relationships
					pairKey := string(providingPkgID) + "-" + string(dependantPkg.ID())
					if seen.Has(pairKey) {
						continue
					}

					providingPkg := pkgsByID[providingPkgID]

					relationships = append(relationships,
						artifact.Relationship{
							From: providingPkg,
							To:   dependantPkg,
							Type: artifact.DependencyOfRelationship,
						},
					)

					seen.Add(pairKey)
				}
			}
		}
	}
	return relationships
}

func allProvides(pkgsProvidingResource map[string]internal.Set[artifact.ID], id artifact.ID, spec Specification) []ProvidesRequires {
	prs := []ProvidesRequires{spec.ProvidesRequires}
	prs = append(prs, spec.Variants...)

	for _, pr := range prs {
		for _, resource := range deduplicate(pr.Provides) {
			if pkgsProvidingResource[resource] == nil {
				pkgsProvidingResource[resource] = internal.NewSet[artifact.ID]()
			}
			pkgsProvidingResource[resource].Add(id)
		}
	}

	return prs
}

func deduplicate(ss []string) []string {
	// note: we sort the set such that multiple invocations of this function will be deterministic
	set := strset.New(ss...)
	list := set.List()
	sort.Strings(list)
	return list
}
