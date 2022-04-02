package pkg

import "github.com/anchore/syft/syft/artifact"

// TODO: as more relationships are added, this function signature will probably accommodate selection
func NewRelationships(catalog *Collection) []artifact.Relationship {
	return RelationshipsByFileOwnership(catalog)
}
