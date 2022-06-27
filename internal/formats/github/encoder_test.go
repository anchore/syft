package github

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func Test_toGithubModel(t *testing.T) {
	s := sbom.SBOM{
		Source: source.Metadata{
			Scheme: source.ImageScheme,
			ImageMetadata: source.ImageMetadata{
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
			PackageCatalog: pkg.NewCatalog(),
		},
	}
	for _, p := range []pkg.Package{
		{
			Name:    "pkg-1",
			Version: "1.0.1",
			Locations: source.NewLocationSet(
				source.Location{
					Coordinates: source.Coordinates{
						RealPath:     "/usr/lib",
						FileSystemID: "fsid-1",
					},
				},
			),
		},
		{
			Name:    "pkg-2",
			Version: "2.0.2",
			Locations: source.NewLocationSet(
				source.Location{
					Coordinates: source.Coordinates{
						RealPath:     "/usr/lib",
						FileSystemID: "fsid-1",
					},
				},
			),
		},
		{
			Name:    "pkg-3",
			Version: "3.0.3",
			Locations: source.NewLocationSet(
				source.Location{
					Coordinates: source.Coordinates{
						RealPath:     "/etc",
						FileSystemID: "fsid-1",
					},
				},
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
		s.Artifacts.PackageCatalog.Add(p)
	}

	actual := toGithubModel(&s)

	expected := DependencySnapshot{
		Version: 0,
		Detector: DetectorMetadata{
			Name:    "syft",
			Version: "0.0.0-dev",
			URL:     "https://github.com/anchore/syft",
		},
		Metadata: Metadata{
			"syft:distro": "pkg:generic/ubuntu@18.04?like=debian",
		},
		Scanned: actual.Scanned,
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
					},
					"pkg:generic/pkg-2@2.0.2": DependencyNode{
						PackageURL:   "pkg:generic/pkg-2@2.0.2",
						Scope:        DependencyScopeRuntime,
						Relationship: DependencyRelationshipDirect,
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
					},
				},
			},
		},
	}

	// just using JSONEq because it gives a comprehensible diff
	s1, _ := json.Marshal(expected)
	s2, _ := json.Marshal(actual)
	assert.JSONEq(t, string(s1), string(s2))

	// Just test the other schemes:
	s.Source.Path = "."
	s.Source.Scheme = source.DirectoryScheme
	actual = toGithubModel(&s)
	assert.Equal(t, "etc", actual.Manifests["etc"].Name)

	s.Source.Path = "./artifacts"
	s.Source.Scheme = source.DirectoryScheme
	actual = toGithubModel(&s)
	assert.Equal(t, "artifacts/etc", actual.Manifests["artifacts/etc"].Name)

	s.Source.Path = "/artifacts"
	s.Source.Scheme = source.DirectoryScheme
	actual = toGithubModel(&s)
	assert.Equal(t, "/artifacts/etc", actual.Manifests["/artifacts/etc"].Name)

	s.Source.Path = "./executable"
	s.Source.Scheme = source.FileScheme
	actual = toGithubModel(&s)
	assert.Equal(t, "executable", actual.Manifests["executable"].Name)

	s.Source.Path = "./archive.tar.gz"
	s.Source.Scheme = source.FileScheme
	actual = toGithubModel(&s)
	assert.Equal(t, "archive.tar.gz:/etc", actual.Manifests["archive.tar.gz:/etc"].Name)
}
