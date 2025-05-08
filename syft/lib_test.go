package syft

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/relationship"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
)

func Test_removeRelationshipsByID(t *testing.T) {
	p1 := pkg.Package{}
	p1.OverrideID("1")

	p2 := pkg.Package{}
	p2.OverrideID("2")

	p3 := pkg.Package{}
	p3.OverrideID("3")

	rel := func(pkgs ...pkg.Package) (out []artifact.Relationship) {
		for _, p := range pkgs {
			out = append(out, artifact.Relationship{
				From: p,
				To:   p,
				Type: artifact.OwnershipByFileOverlapRelationship,
			})
		}
		return
	}

	relationships := rel(p1, p2, p3)

	for _, r := range relationships {
		if r.From.ID() == "1" || r.From.ID() == "2" {
			relationships = relationship.RemoveRelationshipsByID(relationships, r.From.ID())
		}
	}

	require.Equal(t, rel(p3), relationships)
}
