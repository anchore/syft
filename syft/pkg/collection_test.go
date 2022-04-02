package pkg

import (
	"github.com/anchore/syft/syft/file"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scylladb/go-set/strset"
)

type expectedIndexes struct {
	byType map[Type]*strset.Set
	byPath map[string]*strset.Set
}

func TestCatalogAddPopulatesIndex(t *testing.T) {

	var pkgs = []Package{
		{
			Locations: []file.Location{
				file.NewVirtualLocation("/a/path", "/another/path"),
				file.NewVirtualLocation("/b/path", "/bee/path"),
			},
			Type: RpmPkg,
		},
		{
			Locations: []file.Location{
				file.NewVirtualLocation("/c/path", "/another/path"),
				file.NewVirtualLocation("/d/path", "/another/path"),
			},
			Type: NpmPkg,
		},
	}

	for i := range pkgs {
		p := &pkgs[i]
		p.SetID()
	}

	fixtureID := func(i int) string {
		return string(pkgs[i].ID())
	}

	tests := []struct {
		name            string
		expectedIndexes expectedIndexes
	}{
		{
			name: "vanilla-add",
			expectedIndexes: expectedIndexes{
				byType: map[Type]*strset.Set{
					RpmPkg: strset.New(fixtureID(0)),
					NpmPkg: strset.New(fixtureID(1)),
				},
				byPath: map[string]*strset.Set{
					"/another/path": strset.New(fixtureID(0), fixtureID(1)),
					"/a/path":       strset.New(fixtureID(0)),
					"/b/path":       strset.New(fixtureID(0)),
					"/bee/path":     strset.New(fixtureID(0)),
					"/c/path":       strset.New(fixtureID(1)),
					"/d/path":       strset.New(fixtureID(1)),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := NewCollection(pkgs...)

			assertIndexes(t, c, test.expectedIndexes)

		})
	}
}

func assertIndexes(t *testing.T, c *Collection, expectedIndexes expectedIndexes) {
	// assert path index
	assert.Len(t, c.idsByPath, len(expectedIndexes.byPath), "unexpected path index length")
	for path, expectedIds := range expectedIndexes.byPath {
		actualIds := strset.New()
		for _, p := range c.PackagesByPath(path) {
			actualIds.Add(string(p.ID()))
		}

		if !expectedIds.IsEqual(actualIds) {
			t.Errorf("mismatched IDs for path=%q : %+v", path, strset.SymmetricDifference(actualIds, expectedIds))
		}
	}

	// assert type index
	assert.Len(t, c.idsByType, len(expectedIndexes.byType), "unexpected type index length")
	for ty, expectedIds := range expectedIndexes.byType {
		actualIds := strset.New()
		for p := range c.Enumerate(ty) {
			actualIds.Add(string(p.ID()))
		}

		if !expectedIds.IsEqual(actualIds) {
			t.Errorf("mismatched IDs for type=%q : %+v", ty, strset.SymmetricDifference(actualIds, expectedIds))
		}
	}
}

func TestCatalog_PathIndexDeduplicatesRealVsVirtualPaths(t *testing.T) {
	p1 := Package{
		Locations: []file.Location{
			file.NewVirtualLocation("/b/path", "/another/path"),
			file.NewVirtualLocation("/b/path", "/b/path"),
		},
		Type: RpmPkg,
		Name: "Package-1",
	}

	p2 := Package{
		Locations: []file.Location{
			file.NewVirtualLocation("/b/path", "/b/path"),
		},
		Type: RpmPkg,
		Name: "Package-2",
	}
	tests := []struct {
		name string
		pkg  Package
	}{
		{
			name: "multiple locations with shared path",
			pkg:  p1,
		},
		{
			name: "one location with shared path",
			pkg:  p2,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := NewCollection(test.pkg).PackagesByPath("/b/path")
			if len(actual) != 1 {
				t.Errorf("expected exactly one package path, got %d", len(actual))
			}
		})
	}

}

func TestCatalog_EnumerateNilCatalog(t *testing.T) {
	var c *Collection
	assert.Empty(t, c.Enumerate())
}
