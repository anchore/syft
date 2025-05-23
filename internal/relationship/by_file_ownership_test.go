package relationship

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/cmptest"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

type mockFR struct {
	file.Resolver
	translate map[string]string
}

func (m mockFR) FilesByPath(paths ...string) ([]file.Location, error) {
	var results []file.Location
	for _, p := range paths {
		tPath, ok := m.translate[p]
		if !ok {
			tPath = p
		}
		results = append(results, file.NewLocation(tPath))
	}
	return results, nil
}

func TestOwnershipByFilesRelationship(t *testing.T) {

	tests := []struct {
		name     string
		resolver file.Resolver
		setup    func(t testing.TB) ([]pkg.Package, []artifact.Relationship)
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
			name: "only-real-file-owner-gets-ownership-relationship-not-symlink-owner",
			resolver: mockFR{
				translate: map[string]string{
					"/usr/bin/jenkins.war-symlink": "/usr/share/jenkins/jenkins.war", // symlink to the real file
				},
			},
			setup: func(t testing.TB) ([]pkg.Package, []artifact.Relationship) {
				// Package that owns the symlink
				symlinkOwner := pkg.Package{
					Type: pkg.ApkPkg,
					Metadata: pkg.ApkDBEntry{
						Package: "jenkins-symlink-pkg",
						Files: []pkg.ApkFileRecord{
							{Path: "/usr/bin/jenkins.war-symlink"}, // this symlinks to the real file
						},
					},
				}
				symlinkOwner.SetID()

				// Package that owns the real file
				realFileOwner := pkg.Package{
					Type: pkg.ApkPkg,
					Metadata: pkg.ApkDBEntry{
						Package: "jenkins-real-pkg",
						Files: []pkg.ApkFileRecord{
							{Path: "/usr/share/jenkins/jenkins.war"}, // the real file
						},
					},
				}
				realFileOwner.SetID()

				// A third package that is "located at" the real file path
				// This simulates a package being discovered at the jenkins.war location
				consumerPackage := pkg.Package{
					Type: pkg.JavaPkg,
					Locations: file.NewLocationSet(
						file.NewVirtualLocation("/usr/share/jenkins/jenkins.war", "/usr/share/jenkins/jenkins.war"),
					),
				}
				consumerPackage.SetID()

				// Only the real file owner should have an ownership relationship with the consumer package
				// The symlink owner should NOT have a relationship with the consumer
				relationship := artifact.Relationship{
					From: realFileOwner,
					To:   consumerPackage,
					Type: artifact.OwnershipByFileOverlapRelationship,
					Data: ownershipByFilesMetadata{
						Files: []string{
							"/usr/share/jenkins/jenkins.war",
						},
					},
				}

				return []pkg.Package{symlinkOwner, realFileOwner, consumerPackage}, []artifact.Relationship{relationship}
			},
		},
		{
			name: "misses-by-dead-symlink",
			resolver: mockFR{
				translate: map[string]string{
					"/bin/gzip": "", // treat this as a dead symlink
				},
			},
			setup: func(t testing.TB) ([]pkg.Package, []artifact.Relationship) {
				parent := pkg.Package{
					Type: pkg.DebPkg,
					Metadata: pkg.DpkgDBEntry{
						Files: []pkg.DpkgFileRecord{
							{Path: "/bin/gzip"}, // this symlinks to gzip via /bin -> /usr/bin
						},
					},
				}
				parent.SetID()

				child := pkg.Package{
					Locations: file.NewLocationSet(
						file.NewVirtualLocation("/usr/bin/gzip", "/usr/bin/gzip"),
					),
					Type: pkg.BinaryPkg,
				}
				child.SetID()

				return []pkg.Package{parent, child}, nil // importantly, no relationship is expected
			},
		},
		{
			name: "owns-by-symlink",
			resolver: mockFR{
				translate: map[string]string{
					"/bin/gzip": "/usr/bin/gzip", // if there is a string path of /bin/gzip then return the real path of /usr/bin/gzip
				},
			},
			setup: func(t testing.TB) ([]pkg.Package, []artifact.Relationship) {
				parent := pkg.Package{
					Type: pkg.DebPkg,
					Metadata: pkg.DpkgDBEntry{
						Files: []pkg.DpkgFileRecord{
							{Path: "/bin/gzip"}, // this symlinks to gzip via /bin -> /usr/bin
						},
					},
				}
				parent.SetID()

				child := pkg.Package{
					Locations: file.NewLocationSet(
						file.NewVirtualLocation("/usr/bin/gzip", "/usr/bin/gzip"),
					),
					Type: pkg.BinaryPkg,
				}
				child.SetID()

				relationship := artifact.Relationship{
					From: parent,
					To:   child,
					Type: artifact.OwnershipByFileOverlapRelationship,
					Data: ownershipByFilesMetadata{
						Files: []string{
							"/usr/bin/gzip",
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
			relationships := byFileOwnershipOverlap(test.resolver, c)

			require.Len(t, relationships, len(expectedRelations))
			for idx, expectedRelationship := range expectedRelations {
				actualRelationship := relationships[idx]
				if d := cmp.Diff(expectedRelationship, actualRelationship, cmptest.DefaultOptions()...); d != "" {
					t.Errorf("unexpected relationship (-want, +got): %s", d)
				}
			}
		})
	}
}
