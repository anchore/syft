package pkg

import (
	"testing"

	"github.com/anchore/syft/syft/source"
	"github.com/go-test/deep"
)

func TestOwnershipByFilesRelationship(t *testing.T) {
	tests := []struct {
		name              string
		pkgs              []Package
		expectedRelations []Relationship
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
			expectedRelations: []Relationship{
				{
					Parent: "parent",
					Child:  "child",
					Type:   OwnershipByFileOverlapRelationship,
					Metadata: ownershipByFilesMetadata{
						Files: []string{
							"/d/path",
						},
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
			expectedRelations: []Relationship{
				{
					Parent: "parent",
					Child:  "child",
					Type:   OwnershipByFileOverlapRelationship,
					Metadata: ownershipByFilesMetadata{
						Files: []string{
							"/another/path",
						},
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
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := NewCatalog(test.pkgs...)
			relationships := ownershipByFilesRelationships(c)

			for _, d := range deep.Equal(test.expectedRelations, relationships) {
				t.Errorf("diff: %+v", d)
			}
		})
	}
}
