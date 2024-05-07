package dependency

import (
	"sort"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
)

// Prosumer is a producer and consumer, in this context, for packages that provide resources and require resources.
type Prosumer interface {
	Provides(pkg.Package) []string
	Requires(pkg.Package) []string
}

type RelationshipResolver struct {
	prosumer Prosumer
}

func NewRelationshipResolver(p Prosumer) RelationshipResolver {
	return RelationshipResolver{
		prosumer: p,
	}
}

// Resolve will create relationships between packages based on the "Depends" and "Provides" specifications from the given packages.
func (r RelationshipResolver) Resolve(pkgs []pkg.Package) (relationships []artifact.Relationship) {
	lookup := make(map[string][]pkg.Package)

	for _, p := range pkgs {
		for _, key := range deduplicate(r.prosumer.Provides(p)) {
			lookup[key] = append(lookup[key], p)
		}
	}

	seen := strset.New()
	for _, p := range pkgs {
		for _, requirement := range deduplicate(r.prosumer.Requires(p)) {
			for _, depPkg := range lookup[requirement] {
				// prevent creating duplicate relationships
				pairKey := string(depPkg.ID()) + "-" + string(p.ID())
				if seen.Has(pairKey) {
					continue
				}

				relationships = append(relationships,
					artifact.Relationship{
						From: depPkg,
						To:   p,
						Type: artifact.DependencyOfRelationship,
					},
				)

				seen.Add(pairKey)
			}
		}
	}
	return relationships
}

func deduplicate(ss []string) []string {
	set := strset.New(ss...)
	// note: this must be a stable function
	list := set.List()
	sort.Strings(list)
	return list
}

func Resolve(pkgs []pkg.Package, prosumer Prosumer) []artifact.Relationship {
	return NewRelationshipResolver(prosumer).Resolve(pkgs)
}
