package pkg

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/source"
	"github.com/stretchr/testify/assert"
)

func TestOwnershipByFilesRelationship(t *testing.T) {

	tests := []struct {
		name  string
		setup func(t testing.TB) ([]Package, []artifact.Relationship)
	}{
		{
			name: "owns-by-real-path",
			setup: func(t testing.TB) ([]Package, []artifact.Relationship) {
				parent := Package{
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
				}

				child := Package{
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
				}

				relationship := artifact.Relationship{
					From: parent,
					To:   child,
					Type: artifact.OwnershipByFileOverlapRelationship,
					Data: ownershipByFilesMetadata{
						Files: []string{
							"/d/path",
						},
					},
				}

				return []Package{parent, child}, []artifact.Relationship{relationship}
			},
		},
		{
			name: "owns-by-virtual-path",
			setup: func(t testing.TB) ([]Package, []artifact.Relationship) {
				parent := Package{
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
				}

				child := Package{
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
				}

				relationship := artifact.Relationship{
					From: parent,
					To:   child,
					Type: artifact.OwnershipByFileOverlapRelationship,
					Data: ownershipByFilesMetadata{
						Files: []string{
							"/another/path",
						},
					},
				}
				return []Package{parent, child}, []artifact.Relationship{relationship}
			},
		},
		{
			name: "ignore-empty-path",
			setup: func(t testing.TB) ([]Package, []artifact.Relationship) {
				parent := Package{
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
				}

				child := Package{
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
				}

				return []Package{parent, child}, nil
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgs, expectedRelations := test.setup(t)
			c := NewCatalog(pkgs...)
			relationships := ownershipByFilesRelationships(c)

			assert.Len(t, relationships, len(expectedRelations))
			for idx, expectedRelationship := range expectedRelations {
				actualRelationship := relationships[idx]
				assert.Equal(t, expectedRelationship.From.ID(), actualRelationship.From.ID())
				assert.Equal(t, expectedRelationship.To.ID(), actualRelationship.To.ID())
				assert.Equal(t, expectedRelationship.Type, actualRelationship.Type)
				assert.Equal(t, expectedRelationship.Data, actualRelationship.Data)
			}
		})
	}
}
