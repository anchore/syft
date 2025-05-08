package relationship

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
	require.ElementsMatch(t, slice(r1, r2, r3, r4, r5), idx.All())

	require.ElementsMatch(t, slice(r1, r4), idx.References(p2))
	require.ElementsMatch(t, slice(r4), idx.References(p2, artifact.ContainsRelationship))

	require.ElementsMatch(t, slice(r1), idx.To(p2))
	require.ElementsMatch(t, []artifact.Relationship(nil), idx.To(p2, artifact.ContainsRelationship))

	require.ElementsMatch(t, slice(r4), idx.From(p2))
	require.ElementsMatch(t, slice(r4), idx.From(p2, artifact.ContainsRelationship))
}

func Test_sortOrder(t *testing.T) {
	r1 := artifact.Relationship{
		From: id("1"),
		To:   id("2"),
		Type: "1",
	}
	r2 := artifact.Relationship{
		From: id("2"),
		To:   id("3"),
		Type: "1",
	}
	r3 := artifact.Relationship{
		From: id("3"),
		To:   id("4"),
		Type: "1",
	}
	r4 := artifact.Relationship{
		From: id("1"),
		To:   id("2"),
		Type: "2",
	}
	r5 := artifact.Relationship{
		From: id("2"),
		To:   id("3"),
		Type: "2",
	}
	dup := artifact.Relationship{
		From: id("2"),
		To:   id("3"),
		Type: "2",
	}
	r6 := artifact.Relationship{
		From: id("2"),
		To:   id("3"),
		Type: "3",
	}

	idx := NewIndex(r5, r2, r6, r4, r1, r3, dup)
	require.EqualValues(t, slice(r1, r2, r3, r4, r5, r6), idx.All())

	require.EqualValues(t, slice(r1, r4), idx.From(id("1")))

	require.EqualValues(t, slice(r2, r5, r6), idx.To(id("3")))

	rLast := artifact.Relationship{
		From: id("0"),
		To:   id("3"),
		Type: "9999",
	}

	rFirst := artifact.Relationship{
		From: id("0"),
		To:   id("3"),
		Type: "1",
	}

	rMid := artifact.Relationship{
		From: id("0"),
		To:   id("1"),
		Type: "2",
	}

	idx.Add(rLast, rFirst, rMid)

	require.EqualValues(t, slice(rFirst, r1, r2, r3, rMid, r4, r5, r6, rLast), idx.All())

	require.EqualValues(t, slice(rFirst, r2, r5, r6, rLast), idx.To(id("3")))
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
	c3 := file.Coordinates{
		RealPath: "/coords/3",
	}
	c4 := file.Coordinates{
		RealPath: "/coords/4",
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
	r7 := artifact.Relationship{
		From: c1,
		To:   c3,
		Type: artifact.ContainsRelationship,
	}
	r8 := artifact.Relationship{
		From: c3,
		To:   c4,
		Type: artifact.ContainsRelationship,
	}

	idx := NewIndex(r1, r2, r3, r4, r5, r6, r7, r8)

	got := idx.Coordinates(p1)
	require.ElementsMatch(t, slice(c1), got)

	got = idx.Coordinates(p3)
	require.ElementsMatch(t, slice(c1, c2), got)
}

type id string

func (i id) ID() artifact.ID {
	return artifact.ID(i)
}

func slice[T any](values ...T) []T {
	return values
}

func TestRemove(t *testing.T) {
	p1 := pkg.Package{Name: "pkg-1"}
	p2 := pkg.Package{Name: "pkg-2"}
	p3 := pkg.Package{Name: "pkg-3"}
	c1 := file.Coordinates{RealPath: "/coords/1"}
	c2 := file.Coordinates{RealPath: "/coords/2"}
	c3 := file.Coordinates{RealPath: "/coords/3"}
	c4 := file.Coordinates{RealPath: "/coords/4"}

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
	r7 := artifact.Relationship{
		From: c1,
		To:   c3,
		Type: artifact.ContainsRelationship,
	}
	r8 := artifact.Relationship{
		From: c3,
		To:   c4,
		Type: artifact.ContainsRelationship,
	}

	index := NewIndex(r1, r2, r3, r4, r5, r6, r7, r8)

	assert.Equal(t, 8, len(index.All()))

	// removal of p1 should remove r1, r2, and r3
	index.Remove(p1.ID())
	remaining := index.All()

	assert.Equal(t, 5, len(remaining))
	assert.NotContains(t, remaining, r1)
	assert.NotContains(t, remaining, r2)
	assert.NotContains(t, remaining, r3)

	assert.Empty(t, index.From(p1))
	assert.Empty(t, index.To(p1))

	// removal of c1 should remove r5 and r7
	index.Remove(c1.ID())
	remaining = index.All()

	// r8 remains since c3->c4 should still exist
	assert.Equal(t, 3, len(remaining))
	assert.NotContains(t, remaining, r5)
	assert.NotContains(t, remaining, r7)
	assert.Contains(t, remaining, r8)

	assert.Empty(t, index.From(c1))
	assert.Empty(t, index.To(c1))

	// removal of c3 should remove r8
	index.Remove(c3.ID())
	remaining = index.All()

	assert.Equal(t, 2, len(remaining))
	assert.Contains(t, remaining, r4)
	assert.Contains(t, remaining, r6)

	assert.Empty(t, index.From(c3))
	assert.Empty(t, index.To(c3))
}

func TestReplace(t *testing.T) {
	p1 := pkg.Package{Name: "pkg-1"}
	p2 := pkg.Package{Name: "pkg-2"}
	p3 := pkg.Package{Name: "pkg-3"}
	p4 := pkg.Package{Name: "pkg-4"}

	for _, p := range []*pkg.Package{&p1, &p2, &p3, &p4} {
		p.SetID()
	}

	r1 := artifact.Relationship{
		From: p1,
		To:   p2,
		Type: artifact.DependencyOfRelationship,
	}
	r2 := artifact.Relationship{
		From: p3,
		To:   p1,
		Type: artifact.DependencyOfRelationship,
	}
	r3 := artifact.Relationship{
		From: p2,
		To:   p3,
		Type: artifact.ContainsRelationship,
	}

	index := NewIndex(r1, r2, r3)

	// replace p1 with p4 in the relationships
	index.Replace(p1.ID(), &p4)

	expectedRels := []artifact.Relationship{
		{
			From: p4, // replaced
			To:   p2,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: p3,
			To:   p4, // replaced
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: p2,
			To:   p3,
			Type: artifact.ContainsRelationship,
		},
	}

	compareRelationships(t, expectedRels, index.All())
}

func compareRelationships(t testing.TB, expected, actual []artifact.Relationship) {
	assert.Equal(t, len(expected), len(actual), "number of relationships should match")
	for _, e := range expected {
		found := false
		for _, a := range actual {
			if a.From.ID() == e.From.ID() && a.To.ID() == e.To.ID() && a.Type == e.Type {
				found = true
				break
			}
		}
		assert.True(t, found, "expected relationship not found: %+v", e)
	}
}

func TestReplace_NoExistingRelations(t *testing.T) {
	p1 := pkg.Package{Name: "pkg-1"}
	p2 := pkg.Package{Name: "pkg-2"}

	p1.SetID()
	p2.SetID()

	index := NewIndex()

	index.Replace(p1.ID(), &p2)

	allRels := index.All()
	assert.Len(t, allRels, 0)
}
