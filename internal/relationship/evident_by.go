package relationship

import (
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
)

func EvidentBy(catalog *pkg.Collection) []artifact.Relationship {
	var edges []artifact.Relationship
	for _, p := range catalog.Sorted() {
		for _, l := range p.Locations.ToSlice() {
			kind := pkg.SupportingEvidenceAnnotation
			if v, exists := l.Annotations[pkg.EvidenceAnnotationKey]; exists {
				kind = v
			}

			edges = append(edges, artifact.Relationship{
				From: p,
				To:   l.Coordinates,
				Type: artifact.EvidentByRelationship,
				Data: map[string]string{
					"kind": kind,
				},
			})
		}
	}

	return edges
}
