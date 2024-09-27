package relationship

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/internal/cmptest"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func TestOwnershipByFilesRelationship(t *testing.T) {

	tests := []struct {
		name  string
		setup func(t testing.TB) ([]pkg.Package, []artifact.Relationship)
	}{
		{
			name: "owns-by-real-path",
			setup: func(t testing.TB) ([]pkg.Package, []artifact.Relationship) {
				parent := pkg.Package{
					Locations: file.NewLocationSet(
						file.NewVirtualLocation("/a/path", "/another/path"),
						file.NewVirtualLocation("/b/path", "/bee/path"),
					),
					Type: pkg.RpmPkg,
					Metadata: pkg.RpmDBEntry{
						Files: []pkg.RpmFileRecord{
							{Path: "/owning/path/1"},
							{Path: "/owning/path/2"},
							{Path: "/d/path"},
						},
					},
				}
				parent.SetID()

				child := pkg.Package{
					Locations: file.NewLocationSet(
						file.NewVirtualLocation("/c/path", "/another/path"),
						file.NewVirtualLocation("/d/path", "/another/path"),
					),
					Type: pkg.NpmPkg,
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

				return []pkg.Package{parent, child}, []artifact.Relationship{relationship}
			},
		},
		{
			name: "owns-by-virtual-path",
			setup: func(t testing.TB) ([]pkg.Package, []artifact.Relationship) {
				parent := pkg.Package{
					Locations: file.NewLocationSet(
						file.NewVirtualLocation("/a/path", "/some/other/path"),
						file.NewVirtualLocation("/b/path", "/bee/path"),
					),
					Type: pkg.RpmPkg,
					Metadata: pkg.RpmDBEntry{
						Files: []pkg.RpmFileRecord{
							{Path: "/owning/path/1"},
							{Path: "/owning/path/2"},
							{Path: "/another/path"},
						},
					},
				}
				parent.SetID()

				child := pkg.Package{
					Locations: file.NewLocationSet(
						file.NewVirtualLocation("/c/path", "/another/path"),
						file.NewLocation("/d/path"),
					),
					Type: pkg.NpmPkg,
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
				return []pkg.Package{parent, child}, []artifact.Relationship{relationship}
			},
		},
		{
			name: "ignore-empty-path",
			setup: func(t testing.TB) ([]pkg.Package, []artifact.Relationship) {
				parent := pkg.Package{
					Locations: file.NewLocationSet(
						file.NewVirtualLocation("/a/path", "/some/other/path"),
						file.NewVirtualLocation("/b/path", "/bee/path"),
					),
					Type: pkg.RpmPkg,
					Metadata: pkg.RpmDBEntry{
						Files: []pkg.RpmFileRecord{
							{Path: "/owning/path/1"},
							{Path: "/owning/path/2"},
							{Path: ""},
						},
					},
				}

				parent.SetID()

				child := pkg.Package{
					Locations: file.NewLocationSet(
						file.NewVirtualLocation("/c/path", "/another/path"),
						file.NewLocation("/d/path"),
					),
					Type: pkg.NpmPkg,
				}

				child.SetID()

				return []pkg.Package{parent, child}, nil
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgs, expectedRelations := test.setup(t)
			c := pkg.NewCollection(pkgs...)
			relationships := byFileOwnershipOverlap(c)

			assert.Len(t, relationships, len(expectedRelations))
			for idx, expectedRelationship := range expectedRelations {
				actualRelationship := relationships[idx]
				if d := cmp.Diff(expectedRelationship, actualRelationship, cmptest.DefaultCommonOptions()...); d != "" {
					t.Errorf("unexpected relationship (-want, +got): %s", d)
				}
			}
		})
	}
}
