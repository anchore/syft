package dependency

import (
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
		for _, key := range r.prosumer.Provides(p) {
			lookup[key] = append(lookup[key], p)
		}
	}

	for _, p := range pkgs {
		for _, requirement := range r.prosumer.Requires(p) {
			for _, depPkg := range lookup[requirement] {
				relationships = append(relationships, artifact.Relationship{
					From: depPkg,
					To:   p,
					Type: artifact.DependencyOfRelationship,
				})
			}
		}
	}
	return relationships
}

func Resolve(pkgs []pkg.Package, prosumer Prosumer) []artifact.Relationship {
	return NewRelationshipResolver(prosumer).Resolve(pkgs)
}
