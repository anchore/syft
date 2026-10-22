package model

import (
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal/sourcemetadata"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
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
		{
			name:     "snap",
			metadata: source.SnapMetadata{},
			testPath: "name:/etc",
		},
		{
			name:     "oci-model",
			metadata: source.OCIModelMetadata{UserInput: "model-repo/llama:latest"},
			testPath: "model-repo/llama:latest:/etc",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := sbomFixture()

			if test.metadata != nil {
				s.Source.Name = "name"
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

func dependencyGraphFixture(t *testing.T) sbom.SBOM {
	t.Helper()

	newPkg := func(name, version string) pkg.Package {
		p := pkg.Package{
			Name:    name,
			Version: version,
			Locations: file.NewLocationSet(
				file.NewLocationFromCoordinates(file.Coordinates{
					RealPath:     "/app",
					FileSystemID: "fsid-1",
				}),
			),
		}
		p.PURL = packageurl.NewPackageURL("generic", "", name, version, nil, "").ToString()
		p.SetID()
		return p
	}

	pkgs := map[string]pkg.Package{
		"app":        newPkg("app", "1.0.0"),
		"lib":        newPkg("lib", "2.0.0"),
		"alib":       newPkg("alib", "3.0.0"),
		"transitive": newPkg("transitive", "4.0.0"),
		"owner":      newPkg("owner", "5.0.0"),
	}

	s := sbom.SBOM{
		Descriptor: sbom.Descriptor{Name: "syft"},
		Source: source.Description{
			Metadata: source.ImageMetadata{UserInput: "ubuntu:18.04"},
		},
		Artifacts: sbom.Artifacts{Packages: pkg.NewCollection()},
		Relationships: []artifact.Relationship{
			// "lib" and "alib" are dependencies of "app", so they are on the From side
			{From: pkgs["lib"], To: pkgs["app"], Type: artifact.DependencyOfRelationship},
			{From: pkgs["alib"], To: pkgs["app"], Type: artifact.DependencyOfRelationship},
			{From: pkgs["transitive"], To: pkgs["lib"], Type: artifact.DependencyOfRelationship},
			{From: pkgs["transitive"], To: pkgs["alib"], Type: artifact.DependencyOfRelationship},
			// file ownership is not a dependency claim and should not show up as one
			{From: pkgs["owner"], To: pkgs["app"], Type: artifact.OwnershipByFileOverlapRelationship},
		},
	}
	for _, p := range pkgs {
		s.Artifacts.Packages.Add(p)
	}

	return s
}

func Test_toGithubModel_dependencies(t *testing.T) {
	s := dependencyGraphFixture(t)

	resolved := ToGithubModel(&s).Manifests["ubuntu:18.04:/app"].Resolved

	assert.Equal(t, []string{"pkg:generic/alib@3.0.0", "pkg:generic/lib@2.0.0"}, resolved["pkg:generic/app@1.0.0"].Dependencies)
	assert.Equal(t, []string{"pkg:generic/transitive@4.0.0"}, resolved["pkg:generic/lib@2.0.0"].Dependencies)
	assert.Equal(t, []string{"pkg:generic/transitive@4.0.0"}, resolved["pkg:generic/alib@3.0.0"].Dependencies)
	assert.Empty(t, resolved["pkg:generic/transitive@4.0.0"].Dependencies)
	assert.Empty(t, resolved["pkg:generic/owner@5.0.0"].Dependencies)
}

func Test_toGithubModel_dependenciesAreOrderIndependent(t *testing.T) {
	s := dependencyGraphFixture(t)
	forward := ToGithubModel(&s)

	slices.Reverse(s.Relationships)
	reversed := ToGithubModel(&s)

	if d := cmp.Diff(forward.Manifests, reversed.Manifests); d != "" {
		t.Errorf("manifests changed with relationship order (-forward +reversed):\n%s", d)
	}
}
