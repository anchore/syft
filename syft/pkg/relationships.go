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

// SortRelationships takes a set of package-to-package relationships and sorts them in a stable order by name and version.
// Note: this does not consider package-to-other, other-to-package, or other-to-other relationships.
// TODO: ideally this should be replaced with a more type-agnostic sort function that resides in the artifact package.
func SortRelationships(rels []artifact.Relationship) {
	sort.SliceStable(rels, func(i, j int) bool {
		return relationshipLess(rels[i], rels[j])
	})
}

func relationshipLess(i, j artifact.Relationship) bool {
	iFrom, ok1 := i.From.(Package)
	iTo, ok2 := i.To.(Package)
	jFrom, ok3 := j.From.(Package)
	jTo, ok4 := j.To.(Package)

	if !(ok1 && ok2 && ok3 && ok4) {
		return false
	}

	if iFrom.Name != jFrom.Name {
		return iFrom.Name < jFrom.Name
	}
	if iFrom.Version != jFrom.Version {
		return iFrom.Version < jFrom.Version
	}
	if iTo.Name != jTo.Name {
		return iTo.Name < jTo.Name
	}
	if iTo.Version != jTo.Version {
		return iTo.Version < jTo.Version
	}
	return i.Type < j.Type
}
