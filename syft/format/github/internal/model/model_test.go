package model

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/sourcemetadata"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func sbomFixture() sbom.SBOM {
	s := sbom.SBOM{
		Descriptor: sbom.Descriptor{
			Name: "syft",
		},
		Source: source.Description{
			Metadata: source.ImageMetadata{
				UserInput:    "ubuntu:18.04",
				Architecture: "amd64",
			},
		},
		Artifacts: sbom.Artifacts{
			LinuxDistribution: &linux.Release{
				ID:        "ubuntu",
				VersionID: "18.04",
				IDLike:    []string{"debian"},
			},
			Packages: pkg.NewCollection(),
		},
	}
	for _, p := range []pkg.Package{
		{
			Name:    "pkg-1",
			Version: "1.0.1",
			Locations: file.NewLocationSet(
				file.NewLocationFromCoordinates(file.Coordinates{
					RealPath:     "/usr/lib",
					FileSystemID: "fsid-1",
				}),
			),
		},
		{
			Name:    "pkg-2",
			Version: "2.0.2",
			Locations: file.NewLocationSet(
				file.NewLocationFromCoordinates(file.Coordinates{
					RealPath:     "/usr/lib",
					FileSystemID: "fsid-1",
				}),
			),
		},
		{
			Name:    "pkg-3",
			Version: "3.0.3",
			Locations: file.NewLocationSet(
				file.NewLocationFromCoordinates(file.Coordinates{
					RealPath:     "/etc",
					FileSystemID: "fsid-1",
				}),
			),
		},
	} {
		p.PURL = packageurl.NewPackageURL(
			"generic",
			"",
			p.Name,
			p.Version,
			nil,
			"",
		).ToString()
		s.Artifacts.Packages.Add(p)
	}

	return s
}

func Test_toGithubModel(t *testing.T) {
	tracker := sourcemetadata.NewCompletionTester(t)

	tests := []struct {
		name     string
		metadata any
		testPath string
		expected *DependencySnapshot
	}{
		{
			name: "image",
			expected: &DependencySnapshot{
				Version: 0,
				Detector: DetectorMetadata{
					Name:    "syft",
					Version: "0.0.0-dev",
					URL:     "https://github.com/anchore/syft",
				},
				Metadata: Metadata{
					"syft:distro": "pkg:generic/ubuntu@18.04?like=debian",
				},
				//Scanned: actual.Scanned,
				Manifests: Manifests{
					"ubuntu:18.04:/usr/lib": Manifest{
						Name: "ubuntu:18.04:/usr/lib",
						File: FileInfo{
							SourceLocation: "ubuntu:18.04:/usr/lib",
						},
						Metadata: Metadata{
							"syft:filesystem": "fsid-1",
						},
						Resolved: DependencyGraph{
							"pkg:generic/pkg-1@1.0.1": DependencyNode{
								PackageURL:   "pkg:generic/pkg-1@1.0.1",
								Scope:        DependencyScopeRuntime,
								Relationship: DependencyRelationshipDirect,
								Metadata:     Metadata{},
							},
							"pkg:generic/pkg-2@2.0.2": DependencyNode{
								PackageURL:   "pkg:generic/pkg-2@2.0.2",
								Scope:        DependencyScopeRuntime,
								Relationship: DependencyRelationshipDirect,
								Metadata:     Metadata{},
							},
						},
					},
					"ubuntu:18.04:/etc": Manifest{
						Name: "ubuntu:18.04:/etc",
						File: FileInfo{
							SourceLocation: "ubuntu:18.04:/etc",
						},
						Metadata: Metadata{
							"syft:filesystem": "fsid-1",
						},
						Resolved: DependencyGraph{
							"pkg:generic/pkg-3@3.0.3": DependencyNode{
								PackageURL:   "pkg:generic/pkg-3@3.0.3",
								Scope:        DependencyScopeRuntime,
								Relationship: DependencyRelationshipDirect,
								Metadata:     Metadata{},
							},
						},
					},
				},
			},
		},
		{
			name:     "current directory",
			metadata: source.DirectoryMetadata{Path: "."},
			testPath: "etc",
		},
		{
			name:     "relative directory",
			metadata: source.DirectoryMetadata{Path: "./artifacts"},
			testPath: "artifacts/etc",
		},
		{
			name:     "absolute directory",
			metadata: source.DirectoryMetadata{Path: "/artifacts"},
			testPath: "/artifacts/etc",
		},
		{
			name:     "file",
			metadata: source.FileMetadata{Path: "./executable"},
			testPath: "executable",
		},
		{
			name:     "archive",
			metadata: source.FileMetadata{Path: "./archive.tar.gz"},
			testPath: "archive.tar.gz:/etc",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := sbomFixture()

			if test.metadata != nil {
				s.Source.Metadata = test.metadata
			}
			actual := ToGithubModel(&s)

			if test.expected != nil {
				if d := cmp.Diff(*test.expected, actual, cmpopts.IgnoreFields(DependencySnapshot{}, "Scanned")); d != "" {
					t.Errorf("unexpected result (-want +got):\n%s", d)
				}
			}

			assert.Equal(t, test.testPath, actual.Manifests[test.testPath].Name)

			// track each scheme tested (passed or not)
			tracker.Tested(t, s.Source.Metadata)
		})
	}
}
