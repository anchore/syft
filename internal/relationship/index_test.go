package relationship

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

	dup := artifact.Relationship{
		From: p3,
		To:   c2,
		Type: artifact.ContainsRelationship,
	}

	idx := NewIndex(r1, r2, r3, r4, r5, dup)
	require.ElementsMatch(t, slice(r3, r4, r5, r2, r1), idx.All())

	require.ElementsMatch(t, slice(r1, r4), idx.References(p2))
	require.ElementsMatch(t, slice(r4), idx.References(p2, artifact.ContainsRelationship))

	require.ElementsMatch(t, slice(r1), idx.To(p2))
	require.ElementsMatch(t, []artifact.Relationship(nil), idx.To(p2, artifact.ContainsRelationship))

	require.ElementsMatch(t, slice(r4), idx.From(p2))
	require.ElementsMatch(t, slice(r4), idx.From(p2, artifact.ContainsRelationship))
}

func Test_sortOrder(t *testing.T) {
	r1 := artifact.Relationship{
		From: fakeIdentifiable{"1"},
		To:   fakeIdentifiable{"2"},
		Type: artifact.ContainsRelationship,
	}
	r2 := artifact.Relationship{
		From: fakeIdentifiable{"2"},
		To:   fakeIdentifiable{"3"},
		Type: artifact.ContainsRelationship,
	}
	r3 := artifact.Relationship{
		From: fakeIdentifiable{"3"},
		To:   fakeIdentifiable{"4"},
		Type: artifact.ContainsRelationship,
	}
	r4 := artifact.Relationship{
		From: fakeIdentifiable{"1"},
		To:   fakeIdentifiable{"2"},
		Type: artifact.DependencyOfRelationship,
	}
	r5 := artifact.Relationship{
		From: fakeIdentifiable{"2"},
		To:   fakeIdentifiable{"3"},
		Type: artifact.DependencyOfRelationship,
	}
	dup := artifact.Relationship{
		From: fakeIdentifiable{"2"},
		To:   fakeIdentifiable{"3"},
		Type: artifact.DependencyOfRelationship,
	}

	// should have a stable sort order when retrieving elements
	idx := NewIndex(r1, r2, r3, r4, r5, dup)
	require.ElementsMatch(t, slice(r3, r4, r5, r2, r1), idx.All())

	require.ElementsMatch(t, slice(r4, r1), idx.From(fakeIdentifiable{"1"}))
}

func Test_Coordinates(t *testing.T) {
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
		To:   c1,
		Type: artifact.ContainsRelationship,
	}
	r6 := artifact.Relationship{
		From: p3,
		To:   c2,
		Type: artifact.ContainsRelationship,
	}

	idx := NewIndex(r1, r2, r3, r4, r5, r6)

	got := idx.Coordinates(p1)
	require.ElementsMatch(t, slice(c1), got)

	got = idx.Coordinates(p3)
	require.ElementsMatch(t, slice(c1, c2), got)
}

type fakeIdentifiable struct {
	value string
}

func (i fakeIdentifiable) ID() artifact.ID {
	return artifact.ID(i.value)
}

func slice[T any](values ...T) []T {
	return values
}
