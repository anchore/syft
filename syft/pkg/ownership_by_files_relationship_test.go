package pkg

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/artifact"

	"github.com/anchore/syft/syft/source"
)

func TestOwnershipByFilesRelationship(t *testing.T) {
	tests := []struct {
		name              string
		pkgs              []Package
		expectedRelations []artifact.Relationship
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
			expectedRelations: []artifact.Relationship{
				{
					From: "parent",
					To:   "child",
					Type: artifact.OwnershipByFileOverlapRelationship,
					Data: ownershipByFilesMetadata{
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
			expectedRelations: []artifact.Relationship{
				{
					From: "parent",
					To:   "child",
					Type: artifact.OwnershipByFileOverlapRelationship,
					Data: ownershipByFilesMetadata{
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

			assert.Len(t, relationships, len(test.expectedRelations))
			for idx, expectedRelationship := range test.expectedRelations {
				actualRelationship := relationships[idx]
				assert.Equal(t, expectedRelationship.From.Identity(), actualRelationship.From.Identity())
				assert.Equal(t, expectedRelationship.To.Identity(), actualRelationship.To.Identity())
				assert.Equal(t, expectedRelationship.Type, actualRelationship.Type)
				assert.Equal(t, expectedRelationship.Data, actualRelationship.Data)
			}
		})
	}
}
