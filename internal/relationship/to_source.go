package relationship

import (
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
)

func ToSource(src artifact.Identifiable, c *pkg.Collection) []artifact.Relationship {
	relationships := make([]artifact.Relationship, 0) // Should we pre-allocate this by giving catalog a Len() method?
	for p := range c.Enumerate() {
		relationships = append(relationships, artifact.Relationship{
			From: src,
			To:   p,
			Type: artifact.ContainsRelationship,
		})
	}

	return relationships
}
