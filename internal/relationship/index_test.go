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

func TestReplace_NodeOnlyOnToSide(t *testing.T) {
	// regression: a node that only appears on the To side of relationships (nothing depends on it, e.g. a go main
	// module that other modules are a dependency-of) must keep its incoming edges when its ID changes (such as when a
	// compliance rule stubs a missing version and recomputes the package ID). previously the To-side remap guard
	// checked ogID itself instead of the surviving From endpoint, so all such edges were dropped.
	main := pkg.Package{Name: "main-module"} // empty version, like a go main module
	dep1 := pkg.Package{Name: "dep-1", Version: "1.0.0"}
	dep2 := pkg.Package{Name: "dep-2", Version: "2.0.0"}

	for _, p := range []*pkg.Package{&main, &dep1, &dep2} {
		p.SetID()
	}

	// both deps are a dependency-of main; main has no outgoing edges
	r1 := artifact.Relationship{From: dep1, To: main, Type: artifact.DependencyOfRelationship}
	r2 := artifact.Relationship{From: dep2, To: main, Type: artifact.DependencyOfRelationship}

	index := NewIndex(r1, r2)

	// simulate the version stub: main gets a new ID
	stubbedMain := main
	stubbedMain.Version = "UNKNOWN"
	stubbedMain.SetID()
	require.NotEqual(t, main.ID(), stubbedMain.ID())

	index.Replace(main.ID(), &stubbedMain)

	expectedRels := []artifact.Relationship{
		{From: dep1, To: stubbedMain, Type: artifact.DependencyOfRelationship},
		{From: dep2, To: stubbedMain, Type: artifact.DependencyOfRelationship},
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

// Remove must scrub the removed node's edges from adjacent nodes too, otherwise query methods keep returning
// relationships that no longer exist. the original Remove only deleted the removed node's own maps, leaving
// dangling pointers in the other endpoints.
func TestRemove_NoStaleEdgesInAdjacentNodes(t *testing.T) {
	p1 := pkg.Package{Name: "pkg-1", Version: "1"}
	p2 := pkg.Package{Name: "pkg-2", Version: "2"}
	p3 := pkg.Package{Name: "pkg-3", Version: "3"}
	for _, p := range []*pkg.Package{&p1, &p2, &p3} {
		p.SetID()
	}

	r12 := artifact.Relationship{From: p1, To: p2, Type: artifact.DependencyOfRelationship}
	r32 := artifact.Relationship{From: p3, To: p2, Type: artifact.DependencyOfRelationship}
	index := NewIndex(r12, r32)

	index.Remove(p1.ID())

	// p2 was on the To side of the removed edge; its incoming view must no longer include the stale p1 edge,
	// but must still include the live p3 edge.
	compareRelationships(t, []artifact.Relationship{r32}, index.To(p2, artifact.DependencyOfRelationship))
	assert.False(t, index.Contains(r12), "Contains must not report a removed edge")
	assert.Len(t, index.References(p2), 1, "p2 should only reference the surviving p3 edge")
	assert.True(t, index.Contains(r32), "surviving edge should remain")
	compareRelationships(t, []artifact.Relationship{r32}, index.All())
}

// Replace must leave no dangling references to the old ID in adjacent nodes' query views.
func TestReplace_NoStaleEdgesAfterReplace(t *testing.T) {
	main := pkg.Package{Name: "main-module"} // empty version
	dep := pkg.Package{Name: "dep", Version: "1.0.0"}
	main.SetID()
	dep.SetID()

	oldEdge := artifact.Relationship{From: dep, To: main, Type: artifact.DependencyOfRelationship}
	index := NewIndex(oldEdge)

	stubbed := main
	stubbed.Version = "UNKNOWN"
	stubbed.SetID()
	require.NotEqual(t, main.ID(), stubbed.ID())

	index.Replace(main.ID(), &stubbed)

	newEdge := artifact.Relationship{From: dep, To: stubbed, Type: artifact.DependencyOfRelationship}
	// the dep's outgoing view must point at the stubbed node, not the old one
	from := index.From(dep, artifact.DependencyOfRelationship)
	require.Len(t, from, 1)
	assert.Equal(t, stubbed.ID(), from[0].To.ID())
	assert.True(t, index.Contains(newEdge))
	assert.False(t, index.Contains(oldEdge), "stale edge to old ID must be gone")
	assert.Empty(t, index.To(main), "old node should have no incoming edges")
	compareRelationships(t, []artifact.Relationship{newEdge}, index.All())
}

// replacing a node with one that has the same ID must be a no-op, not silently wipe its edges.
func TestReplace_SameIDIsNoOp(t *testing.T) {
	a := pkg.Package{Name: "a", Version: "1"}
	b := pkg.Package{Name: "b", Version: "2"}
	a.SetID()
	b.SetID()
	edge := artifact.Relationship{From: a, To: b, Type: artifact.DependencyOfRelationship}
	index := NewIndex(edge)

	// same identity object -> same ID
	index.Replace(b.ID(), b)

	compareRelationships(t, []artifact.Relationship{edge}, index.All())
	assert.True(t, index.Contains(edge))
}

// a self-edge on the replaced node should be remapped to replacement->replacement, not dropped.
func TestReplace_SelfEdge(t *testing.T) {
	n := pkg.Package{Name: "n"} // empty version
	n.SetID()
	index := NewIndex(artifact.Relationship{From: n, To: n, Type: artifact.DependencyOfRelationship})

	sn := n
	sn.Version = "UNKNOWN"
	sn.SetID()
	require.NotEqual(t, n.ID(), sn.ID())

	index.Replace(n.ID(), &sn)

	all := index.All()
	require.Len(t, all, 1)
	assert.Equal(t, sn.ID(), all[0].From.ID())
	assert.Equal(t, sn.ID(), all[0].To.ID())
	assert.Empty(t, index.From(n), "no edges should reference the old ID")
	assert.Empty(t, index.To(n), "no edges should reference the old ID")
}
