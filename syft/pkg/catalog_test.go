package pkg

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/source"
	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type expectedIndexes struct {
	byType map[Type]*strset.Set
	byPath map[string]*strset.Set
}

func TestCatalogAddPopulatesIndex(t *testing.T) {

	var pkgs = []Package{
		{
			Locations: source.NewLocationSet(
				source.NewVirtualLocation("/a/path", "/another/path"),
				source.NewVirtualLocation("/b/path", "/bee/path"),
			),
			Type: RpmPkg,
		},
		{
			Locations: source.NewLocationSet(
				source.NewVirtualLocation("/c/path", "/another/path"),
				source.NewVirtualLocation("/d/path", "/another/path"),
			),
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
			c := NewCatalog(pkgs...)

			assertIndexes(t, c, test.expectedIndexes)

		})
	}
}

func assertIndexes(t *testing.T, c *Catalog, expectedIndexes expectedIndexes) {
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
		Locations: source.NewLocationSet(
			source.NewVirtualLocation("/b/path", "/another/path"),
			source.NewVirtualLocation("/b/path", "/b/path"),
		),
		Type: RpmPkg,
		Name: "Package-1",
	}

	p2 := Package{
		Locations: source.NewLocationSet(
			source.NewVirtualLocation("/b/path", "/b/path"),
		),
		Type: RpmPkg,
		Name: "Package-2",
	}
	p2Dup := Package{
		Locations: source.NewLocationSet(
			source.NewVirtualLocation("/b/path", "/another/path"),
			source.NewVirtualLocation("/b/path", "/c/path/b/dup"),
		),
		Type: RpmPkg,
		Name: "Package-2",
	}

	tests := []struct {
		name  string
		pkgs  []Package
		paths []string
	}{
		{
			name: "multiple locations with shared path",
			pkgs: []Package{p1},
			paths: []string{
				"/b/path",
				"/another/path",
			},
		},
		{
			name: "one location with shared path",
			pkgs: []Package{p2},
			paths: []string{
				"/b/path",
			},
		},
		{
			name: "two instances with similar locations",
			pkgs: []Package{p2, p2Dup},
			paths: []string{
				"/b/path",
				"/another/path",
				"/c/path/b/dup", // this updated the path index on merge
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, path := range test.paths {
				actualPackages := NewCatalog(test.pkgs...).PackagesByPath(path)
				require.Len(t, actualPackages, 1)
			}
		})
	}

}

func TestCatalog_MergeRecords(t *testing.T) {
	var tests = []struct {
		name              string
		pkgs              []Package
		expectedLocations []source.Location
	}{
		{
			name: "multiple Locations with shared path",
			pkgs: []Package{
				{
					Locations: source.NewLocationSet(
						source.Location{
							Coordinates: source.Coordinates{
								RealPath:     "/b/path",
								FileSystemID: "a",
							},
							VirtualPath: "/another/path",
						},
					),
					Type: RpmPkg,
				},
				{
					Locations: source.NewLocationSet(
						source.Location{
							Coordinates: source.Coordinates{
								RealPath:     "/b/path",
								FileSystemID: "b",
							},
							VirtualPath: "/another/path",
						},
					),
					Type: RpmPkg,
				},
			},
			expectedLocations: []source.Location{
				{
					Coordinates: source.Coordinates{
						RealPath:     "/b/path",
						FileSystemID: "a",
					},
					VirtualPath: "/another/path",
				},
				{
					Coordinates: source.Coordinates{
						RealPath:     "/b/path",
						FileSystemID: "b",
					},
					VirtualPath: "/another/path",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := NewCatalog(tt.pkgs...).PackagesByPath("/b/path")
			require.Len(t, actual, 1)
			assert.Equal(t, tt.expectedLocations, actual[0].Locations.ToSlice())
		})
	}
}

func TestCatalog_EnumerateNilCatalog(t *testing.T) {
	var c *Catalog
	assert.Empty(t, c.Enumerate())
}

func Test_idOrderedSet_add(t *testing.T) {
	tests := []struct {
		name     string
		input    []artifact.ID
		expected []artifact.ID
	}{
		{
			name: "elements deduplicated when added",
			input: []artifact.ID{
				"1", "2", "3", "4", "1", "2", "3", "4", "1", "2", "3", "4",
			},
			expected: []artifact.ID{
				"1", "2", "3", "4",
			},
		},
		{
			name: "elements retain ordering when added",
			input: []artifact.ID{
				"4", "3", "2", "1",
			},
			expected: []artifact.ID{
				"4", "3", "2", "1",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var s orderedIDSet
			s.add(tt.input...)
			assert.Equal(t, tt.expected, s.slice)
		})
	}
}
