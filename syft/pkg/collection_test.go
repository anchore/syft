package pkg

import (
	"testing"

	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
)

type expectedIndexes struct {
	byType map[Type]*strset.Set
	byPath map[string]*strset.Set
}

func TestCatalogMergePackageLicenses(t *testing.T) {
	tests := []struct {
		name         string
		pkgs         []Package
		expectedPkgs []Package
	}{
		{
			name: "merges licenses of packages with equal ID",
			pkgs: []Package{
				{
					id: "equal",
					Licenses: NewLicenseSet(
						NewLicensesFromValues("foo", "baq", "quz")...,
					),
				},
				{
					id: "equal",
					Licenses: NewLicenseSet(
						NewLicensesFromValues("bar", "baz", "foo", "qux")...,
					),
				},
			},
			expectedPkgs: []Package{
				{
					id: "equal",
					Licenses: NewLicenseSet(
						NewLicensesFromValues("foo", "baq", "quz", "qux", "bar", "baz")...,
					),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			collection := NewCollection(test.pkgs...)
			for i, p := range collection.Sorted() {
				assert.Equal(t, test.expectedPkgs[i].Licenses, p.Licenses)
			}
		})
	}
}

func TestCatalogDeleteRemovesPackages(t *testing.T) {
	tests := []struct {
		name            string
		pkgs            []Package
		deleteIDs       []artifact.ID
		expectedIndexes expectedIndexes
	}{
		{
			name: "delete one package",
			pkgs: []Package{
				{
					id:      "pkg:deb/debian/1",
					Name:    "debian",
					Version: "1",
					Type:    DebPkg,
					Locations: file.NewLocationSet(
						file.NewVirtualLocation("/c/path", "/another/path1"),
					),
				},
				{
					id:      "pkg:deb/debian/2",
					Name:    "debian",
					Version: "2",
					Type:    DebPkg,
					Locations: file.NewLocationSet(
						file.NewVirtualLocation("/d/path", "/another/path2"),
					),
				},
			},
			deleteIDs: []artifact.ID{
				artifact.ID("pkg:deb/debian/1"),
			},
			expectedIndexes: expectedIndexes{
				byType: map[Type]*strset.Set{
					DebPkg: strset.New("pkg:deb/debian/2"),
				},
				byPath: map[string]*strset.Set{
					"/d/path":        strset.New("pkg:deb/debian/2"),
					"/another/path2": strset.New("pkg:deb/debian/2"),
				},
			},
		},
		{
			name: "delete multiple packages",
			pkgs: []Package{
				{
					id:      "pkg:deb/debian/1",
					Name:    "debian",
					Version: "1",
					Type:    DebPkg,
					Locations: file.NewLocationSet(
						file.NewVirtualLocation("/c/path", "/another/path1"),
					),
				},
				{
					id:      "pkg:deb/debian/2",
					Name:    "debian",
					Version: "2",
					Type:    DebPkg,
					Locations: file.NewLocationSet(
						file.NewVirtualLocation("/d/path", "/another/path2"),
					),
				},
				{
					id:      "pkg:deb/debian/3",
					Name:    "debian",
					Version: "3",
					Type:    DebPkg,
					Locations: file.NewLocationSet(
						file.NewVirtualLocation("/e/path", "/another/path3"),
					),
				},
			},
			deleteIDs: []artifact.ID{
				artifact.ID("pkg:deb/debian/1"),
				artifact.ID("pkg:deb/debian/3"),
			},
			expectedIndexes: expectedIndexes{
				byType: map[Type]*strset.Set{
					DebPkg: strset.New("pkg:deb/debian/2"),
				},
				byPath: map[string]*strset.Set{
					"/d/path":        strset.New("pkg:deb/debian/2"),
					"/another/path2": strset.New("pkg:deb/debian/2"),
				},
			},
		},
		{
			name: "delete non-existent package",
			pkgs: []Package{
				{
					id:      artifact.ID("pkg:deb/debian/1"),
					Name:    "debian",
					Version: "1",
					Type:    DebPkg,
					Locations: file.NewLocationSet(
						file.NewVirtualLocation("/c/path", "/another/path1"),
					),
				},
				{
					id:      artifact.ID("pkg:deb/debian/2"),
					Name:    "debian",
					Version: "2",
					Type:    DebPkg,
					Locations: file.NewLocationSet(
						file.NewVirtualLocation("/d/path", "/another/path2"),
					),
				},
			},
			deleteIDs: []artifact.ID{
				artifact.ID("pkg:deb/debian/3"),
			},
			expectedIndexes: expectedIndexes{
				byType: map[Type]*strset.Set{
					DebPkg: strset.New("pkg:deb/debian/1", "pkg:deb/debian/2"),
				},
				byPath: map[string]*strset.Set{
					"/c/path":        strset.New("pkg:deb/debian/1"),
					"/another/path1": strset.New("pkg:deb/debian/1"),
					"/d/path":        strset.New("pkg:deb/debian/2"),
					"/another/path2": strset.New("pkg:deb/debian/2"),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := NewCollection()
			for _, p := range test.pkgs {
				c.Add(p)
			}

			for _, id := range test.deleteIDs {
				c.Delete(id)
			}

			assertIndexes(t, c, test.expectedIndexes)
		})
	}
}

func TestCatalogAddPopulatesIndex(t *testing.T) {

	var pkgs = []Package{
		{
			Locations: file.NewLocationSet(
				file.NewVirtualLocation("/a/path", "/another/path"),
				file.NewVirtualLocation("/b/path", "/bee/path"),
			),
			Type: RpmPkg,
		},
		{
			Locations: file.NewLocationSet(
				file.NewVirtualLocation("/c/path", "/another/path"),
				file.NewVirtualLocation("/d/path", "/another/path"),
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
		Locations: file.NewLocationSet(
			file.NewVirtualLocation("/b/path", "/another/path"),
			file.NewVirtualLocation("/b/path", "/b/path"),
		),
		Type: RpmPkg,
		Name: "Package-1",
	}

	p2 := Package{
		Locations: file.NewLocationSet(
			file.NewVirtualLocation("/b/path", "/b/path"),
		),
		Type: RpmPkg,
		Name: "Package-2",
	}
	p2Dup := Package{
		Locations: file.NewLocationSet(
			file.NewVirtualLocation("/b/path", "/another/path"),
			file.NewVirtualLocation("/b/path", "/c/path/b/dup"),
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
				actualPackages := NewCollection(test.pkgs...).PackagesByPath(path)
				require.Len(t, actualPackages, 1)
			}
		})
	}

}

func TestCatalog_MergeRecords(t *testing.T) {
	var tests = []struct {
		name              string
		pkgs              []Package
		expectedLocations []file.Location
		expectedCPECount  int
	}{
		{
			name: "multiple Locations with shared path",
			pkgs: []Package{
				{
					CPEs: []cpe.CPE{cpe.Must("cpe:2.3:a:package:1:1:*:*:*:*:*:*:*", cpe.GeneratedSource)},
					Locations: file.NewLocationSet(
						file.NewVirtualLocationFromCoordinates(
							file.Coordinates{
								RealPath:     "/b/path",
								FileSystemID: "a",
							},
							"/another/path",
						),
					),
					Type: RpmPkg,
				},
				{
					CPEs: []cpe.CPE{cpe.Must("cpe:2.3:a:package:2:2:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource)},
					Locations: file.NewLocationSet(
						file.NewVirtualLocationFromCoordinates(
							file.Coordinates{
								RealPath:     "/b/path",
								FileSystemID: "b",
							},
							"/another/path",
						),
					),
					Type: RpmPkg,
				},
			},
			expectedLocations: []file.Location{
				file.NewVirtualLocationFromCoordinates(
					file.Coordinates{
						RealPath:     "/b/path",
						FileSystemID: "a",
					},
					"/another/path",
				),
				file.NewVirtualLocationFromCoordinates(
					file.Coordinates{
						RealPath:     "/b/path",
						FileSystemID: "b",
					},
					"/another/path",
				),
			},
			expectedCPECount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := NewCollection(tt.pkgs...).PackagesByPath("/b/path")
			require.Len(t, actual, 1)
			assert.Equal(t, tt.expectedLocations, actual[0].Locations.ToSlice())
			require.Len(t, actual[0].CPEs, tt.expectedCPECount)
		})
	}
}

func TestCatalog_EnumerateNilCatalog(t *testing.T) {
	var c *Collection
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
