package relationship

import (
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
)

func evidentBy(catalog *pkg.Collection) []artifact.Relationship {
	var edges []artifact.Relationship
	for _, p := range catalog.Sorted() {
		for _, l := range p.Locations.ToSlice() {
			if v, exists := l.Annotations[pkg.EvidenceAnnotationKey]; !exists || v != pkg.PrimaryEvidenceAnnotation {
				// skip non-primary evidence from being expressed as a relationship.
				// note: this may be configurable in the future.
				continue
			}
			edges = append(edges, artifact.Relationship{
				From: p,
				To:   l.Coordinates,
				Type: artifact.EvidentByRelationship,
			})
		}
	}

	return edges
}
