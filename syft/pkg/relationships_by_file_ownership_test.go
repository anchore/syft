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
					Locations: source.NewLocationSet(
						source.NewVirtualLocation("/a/path", "/another/path"),
						source.NewVirtualLocation("/b/path", "/bee/path"),
					),
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
				parent.SetID()

				child := Package{
					Locations: source.NewLocationSet(
						source.NewVirtualLocation("/c/path", "/another/path"),
						source.NewVirtualLocation("/d/path", "/another/path"),
					),
					Type: NpmPkg,
				}
				child.SetID()

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
					Locations: source.NewLocationSet(
						source.NewVirtualLocation("/a/path", "/some/other/path"),
						source.NewVirtualLocation("/b/path", "/bee/path"),
					),
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
				parent.SetID()

				child := Package{
					Locations: source.NewLocationSet(
						source.NewVirtualLocation("/c/path", "/another/path"),
						source.NewLocation("/d/path"),
					),
					Type: NpmPkg,
				}
				child.SetID()

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
					Locations: source.NewLocationSet(
						source.NewVirtualLocation("/a/path", "/some/other/path"),
						source.NewVirtualLocation("/b/path", "/bee/path"),
					),
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

				parent.SetID()

				child := Package{
					Locations: source.NewLocationSet(
						source.NewVirtualLocation("/c/path", "/another/path"),
						source.NewLocation("/d/path"),
					),
					Type: NpmPkg,
				}

				child.SetID()

				return []Package{parent, child}, nil
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgs, expectedRelations := test.setup(t)
			c := NewCatalog(pkgs...)
			relationships := RelationshipsByFileOwnership(c)

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
