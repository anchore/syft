package pkg

import (
	"testing"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/syft/source"
)

var catalogAddAndRemoveTestPkgs = []Package{
	{
		Locations: []source.Location{
			{
				RealPath:    "/a/path",
				VirtualPath: "/another/path",
			},
			{
				RealPath:    "/b/path",
				VirtualPath: "/bee/path",
			},
		},
		Type: RpmPkg,
	},
	{
		Locations: []source.Location{
			{
				RealPath:    "/c/path",
				VirtualPath: "/another/path",
			},
			{
				RealPath:    "/d/path",
				VirtualPath: "/another/path",
			},
		},
		Type: NpmPkg,
	},
}

type expectedIndexes struct {
	byType map[Type]*strset.Set
	byPath map[string]*strset.Set
}

func TestCatalogAddPopulatesIndex(t *testing.T) {

	fixtureID := func(i int) string {
		return string(catalogAddAndRemoveTestPkgs[i].Identity())
	}

	tests := []struct {
		name            string
		pkgs            []Package
		expectedIndexes expectedIndexes
	}{
		{
			name: "vanilla-add",
			pkgs: catalogAddAndRemoveTestPkgs,
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
			c := NewCatalog(test.pkgs...)

			assertIndexes(t, c, test.expectedIndexes)

		})
	}
}

func assertIndexes(t *testing.T, c *Catalog, expectedIndexes expectedIndexes) {
	// assert path index
	if len(c.idsByPath) != len(expectedIndexes.byPath) {
		t.Errorf("unexpected path index length: %d != %d", len(c.idsByPath), len(expectedIndexes.byPath))
	}
	for path, expectedIds := range expectedIndexes.byPath {
		actualIds := strset.New()
		for _, p := range c.PackagesByPath(path) {
			actualIds.Add(string(p.Identity()))
		}

		if !expectedIds.IsEqual(actualIds) {
			t.Errorf("mismatched IDs for path=%q : %+v", path, strset.SymmetricDifference(actualIds, expectedIds))
		}
	}

	// assert type index
	if len(c.idsByType) != len(expectedIndexes.byType) {
		t.Errorf("unexpected type index length: %d != %d", len(c.idsByType), len(expectedIndexes.byType))
	}
	for ty, expectedIds := range expectedIndexes.byType {
		actualIds := strset.New()
		for p := range c.Enumerate(ty) {
			actualIds.Add(string(p.Identity()))
		}

		if !expectedIds.IsEqual(actualIds) {
			t.Errorf("mismatched IDs for type=%q : %+v", ty, strset.SymmetricDifference(actualIds, expectedIds))
		}
	}
}

func TestCatalog_PathIndexDeduplicatesRealVsVirtualPaths(t *testing.T) {
	p1 := Package{
		Locations: []source.Location{
			{
				RealPath:    "/b/path",
				VirtualPath: "/another/path",
			},
			{
				RealPath:    "/b/path",
				VirtualPath: "/b/path",
			},
		},
		Type: RpmPkg,
		Name: "Package-1",
	}

	p2 := Package{
		Locations: []source.Location{
			{
				RealPath:    "/b/path",
				VirtualPath: "/b/path",
			},
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
			actual := NewCatalog(test.pkg).PackagesByPath("/b/path")
			if len(actual) != 1 {
				t.Errorf("expected exactly one package path, got %d", len(actual))
			}
		})
	}

}
