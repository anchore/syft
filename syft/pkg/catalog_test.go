package pkg

import (
	"testing"

	"github.com/go-test/deep"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/syft/source"
)

var catalogAddAndRemoveTestPkgs = []Package{
	{
		ID: "my-id",
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
		ID: "my-other-id",
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
					RpmPkg: strset.New("my-id"),
					NpmPkg: strset.New("my-other-id"),
				},
				byPath: map[string]*strset.Set{
					"/another/path": strset.New("my-id", "my-other-id"),
					"/a/path":       strset.New("my-id"),
					"/b/path":       strset.New("my-id"),
					"/bee/path":     strset.New("my-id"),
					"/c/path":       strset.New("my-other-id"),
					"/d/path":       strset.New("my-other-id"),
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

func TestCatalogRemove(t *testing.T) {
	tests := []struct {
		name            string
		pkgs            []Package
		removeId        ID
		expectedIndexes expectedIndexes
	}{
		{
			name:     "vanilla-add",
			removeId: "my-other-id",
			pkgs:     catalogAddAndRemoveTestPkgs,
			expectedIndexes: expectedIndexes{
				byType: map[Type]*strset.Set{
					RpmPkg: strset.New("my-id"),
				},
				byPath: map[string]*strset.Set{
					"/another/path": strset.New("my-id"),
					"/a/path":       strset.New("my-id"),
					"/b/path":       strset.New("my-id"),
					"/bee/path":     strset.New("my-id"),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := NewCatalog(test.pkgs...)
			c.Remove(test.removeId)

			assertIndexes(t, c, test.expectedIndexes)

			if c.Package(test.removeId) != nil {
				t.Errorf("expected package to be removed, but was found!")
			}

			if c.PackageCount() != len(test.pkgs)-1 {
				t.Errorf("expected count to be affected but was not")
			}

		})
	}
}

func TestCatalogMarkOwnership(t *testing.T) {
	tests := []struct {
		name              string
		pkgs              []Package
		expectedRelations map[ID]Relations
	}{
		{
			name: "owns-by-real-path",
			pkgs: []Package{
				{
					ID: "parent",
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
					Type:         RpmPkg,
					MetadataType: RpmdbMetadataType,
					Metadata: RpmdbMetadata{
						Files: []RpmdbFileRecord{
							{Path: "/owning/path/1"},
							{Path: "/owning/path/2"},
							{Path: "/d/path"},
						},
					},
				},
				{
					ID: "child",
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
			},
			expectedRelations: map[ID]Relations{
				"parent": {},
				"child": {
					ParentsByFileOwnership: []ID{
						"parent",
					},
				},
			},
		},
		{
			name: "owns-by-virtual-path",
			pkgs: []Package{
				{
					ID: "parent",
					Locations: []source.Location{
						{
							RealPath:    "/a/path",
							VirtualPath: "/some/other/path",
						},
						{
							RealPath:    "/b/path",
							VirtualPath: "/bee/path",
						},
					},
					Type:         RpmPkg,
					MetadataType: RpmdbMetadataType,
					Metadata: RpmdbMetadata{
						Files: []RpmdbFileRecord{
							{Path: "/owning/path/1"},
							{Path: "/owning/path/2"},
							{Path: "/another/path"},
						},
					},
				},
				{
					ID: "child",
					Locations: []source.Location{
						{
							RealPath:    "/c/path",
							VirtualPath: "/another/path",
						},
						{
							RealPath:    "/d/path",
							VirtualPath: "",
						},
					},
					Type: NpmPkg,
				},
			},
			expectedRelations: map[ID]Relations{
				"parent": {},
				"child": {
					ParentsByFileOwnership: []ID{
						"parent",
					},
				},
			},
		},
		{
			name: "ignore-empty-path",
			pkgs: []Package{
				{
					ID: "parent",
					Locations: []source.Location{
						{
							RealPath:    "/a/path",
							VirtualPath: "/some/other/path",
						},
						{
							RealPath:    "/b/path",
							VirtualPath: "/bee/path",
						},
					},
					Type:         RpmPkg,
					MetadataType: RpmdbMetadataType,
					Metadata: RpmdbMetadata{
						Files: []RpmdbFileRecord{
							{Path: "/owning/path/1"},
							{Path: "/owning/path/2"},
							{Path: ""},
						},
					},
				},
				{
					ID: "child",
					Locations: []source.Location{
						{
							RealPath:    "/c/path",
							VirtualPath: "/another/path",
						},
						{
							RealPath:    "/d/path",
							VirtualPath: "",
						},
					},
					Type: NpmPkg,
				},
			},
			expectedRelations: map[ID]Relations{
				"parent": {},
				"child":  {},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := NewCatalog(test.pkgs...)
			c.markPackageOwnership()

			for p := range c.Enumerate() {
				expectedRelations := test.expectedRelations[p.ID]
				actualRelations := p.Relations

				for _, d := range deep.Equal(expectedRelations, actualRelations) {
					t.Errorf("diff: %+v", d)
				}
			}
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
			actualIds.Add(string(p.ID))
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
			actualIds.Add(string(p.ID))
		}

		if !expectedIds.IsEqual(actualIds) {
			t.Errorf("mismatched IDs for type=%q : %+v", ty, strset.SymmetricDifference(actualIds, expectedIds))
		}
	}
}
