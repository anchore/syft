package pkg

import (
	"github.com/anchore/syft/syft/artifact"
)

func RelationshipsEvidentBy(catalog *Catalog) []artifact.Relationship {
	var edges []artifact.Relationship
	for _, p := range catalog.Sorted() {
		for _, l := range p.Locations.ToSlice() {
			edges = append(edges, artifact.Relationship{
				From: p,
				To:   l.Coordinates,
				Type: artifact.EvidentByRelationship,
			})
		}
	}

	return edges
}
