package relationships

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func Test_Index(t *testing.T) {
	p1 := pkg.Package{
		Name: "pkg-1",
	}
	p2 := pkg.Package{
		Name: "pkg-2",
	}
	p3 := pkg.Package{
		Name: "pkg-3",
	}
	c1 := file.Coordinates{
		RealPath: "/coords/1",
	}
	c2 := file.Coordinates{
		RealPath: "/coords/2",
	}

	for _, p := range []*pkg.Package{&p1, &p2, &p3} {
		p.SetID()
	}

	r1 := artifact.Relationship{
		From: p1,
		To:   p2,
		Type: artifact.DependencyOfRelationship,
	}
	r2 := artifact.Relationship{
		From: p1,
		To:   p3,
		Type: artifact.DependencyOfRelationship,
	}
	r3 := artifact.Relationship{
		From: p1,
		To:   c1,
		Type: artifact.ContainsRelationship,
	}
	r4 := artifact.Relationship{
		From: p2,
		To:   c2,
		Type: artifact.ContainsRelationship,
	}
	r5 := artifact.Relationship{
		From: p3,
		To:   c2,
		Type: artifact.ContainsRelationship,
	}

	idx := NewIndex([]artifact.Relationship{r1, r2, r3, r4, r5})

	require.EqualValues(t, idx.ToAndFrom(p2), rels(r1, r4))
	require.EqualValues(t, idx.ToAndFrom(p2, artifact.ContainsRelationship), rels(r4))

	require.EqualValues(t, idx.To(p2), rels(r1))
	require.EqualValues(t, idx.To(p2, artifact.ContainsRelationship), rels())

	require.EqualValues(t, idx.From(p2), rels(r4))
	require.EqualValues(t, idx.From(p2, artifact.ContainsRelationship), rels(r4))
}

func rels(values ...artifact.Relationship) []artifact.Relationship {
	return values
}
