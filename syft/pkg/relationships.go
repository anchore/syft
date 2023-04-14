package pkg

import "github.com/anchore/syft/syft/artifact"

func NewRelationships(catalog *Catalog) []artifact.Relationship {
	rels := RelationshipsByFileOwnership(catalog)
	rels = append(rels, RelationshipsEvidentBy(catalog)...)
	return rels
}
