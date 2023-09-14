package pkg

import (
	"sort"

	"github.com/anchore/syft/syft/artifact"
)

func NewRelationships(catalog *Collection) []artifact.Relationship {
	rels := RelationshipsByFileOwnership(catalog)
	rels = append(rels, RelationshipsEvidentBy(catalog)...)
	return rels
}

func RelationshipLess(i, j artifact.Relationship) bool {
	iFromPkg, ok1 := i.From.(*Package)
	iToPkg, ok2 := i.To.(*Package)
	jFromPkg, ok3 := j.From.(*Package)
	jToPkg, ok4 := j.To.(*Package)

	// Check type assertions, and if any fails, return false
	if !(ok1 && ok2 && ok3 && ok4) {
		return false
	}

	// Deterministically compare fields
	switch {
	case iFromPkg.Name != jFromPkg.Name:
		return iFromPkg.Name < jFromPkg.Name
	case iFromPkg.Version != jFromPkg.Version:
		return iFromPkg.Version < jFromPkg.Version
	case iToPkg.Name != jToPkg.Name:
		return iToPkg.Name < jToPkg.Name
	case iToPkg.Version != jToPkg.Version:
		return iToPkg.Version < jToPkg.Version
	default:
		return i.Type < j.Type
	}
}

func SortRelationships(rels []artifact.Relationship) {
	sort.SliceStable(rels, func(i, j int) bool {
		return RelationshipLess(rels[i], rels[j])
	})
}
