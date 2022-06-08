package syftjson

import (
	"flag"
	"testing"

	"github.com/anchore/syft/syft/file"

	"github.com/anchore/syft/syft/artifact"

	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"

	"github.com/anchore/syft/internal/formats/common/testutils"
)

var updateJson = flag.Bool("update-json", false, "update the *.golden files for json encoders")

func TestDirectoryEncoder(t *testing.T) {
	testutils.AssertEncoderAgainstGoldenSnapshot(t,
		Format(),
		testutils.DirectoryInput(t),
		*updateJson,
	)
}

func TestImageEncoder(t *testing.T) {
	testImage := "image-simple"
	testutils.AssertEncoderAgainstGoldenImageSnapshot(t,
		Format(),
		testutils.ImageInput(t, testImage, testutils.FromSnapshot()),
		testImage,
		*updateJson,
	)
}

func TestEncodeFullJSONDocument(t *testing.T) {
	catalog := pkg.NewCatalog()

	p1 := pkg.Package{
		Name:    "package-1",
		Version: "1.0.1",
		Locations: source.NewLocationSet(
			source.Location{
				Coordinates: source.Coordinates{
					RealPath: "/a/place/a",
				},
			},
		),
		Type:         pkg.PythonPkg,
		FoundBy:      "the-cataloger-1",
		Language:     pkg.Python,
		MetadataType: pkg.PythonPackageMetadataType,
		Licenses:     []string{"MIT"},
		Metadata: pkg.PythonPackageMetadata{
			Name:    "package-1",
			Version: "1.0.1",
			Files:   []pkg.PythonFileRecord{},
		},
		PURL: "a-purl-1",
		CPEs: []pkg.CPE{
			pkg.MustCPE("cpe:2.3:*:some:package:1:*:*:*:*:*:*:*"),
		},
	}

	p2 := pkg.Package{
		Name:    "package-2",
		Version: "2.0.1",
		Locations: source.NewLocationSet(
			source.Location{
				Coordinates: source.Coordinates{
					RealPath: "/b/place/b",
				},
			},
		),
		Type:         pkg.DebPkg,
		FoundBy:      "the-cataloger-2",
		MetadataType: pkg.DpkgMetadataType,
		Metadata: pkg.DpkgMetadata{
			Package: "package-2",
			Version: "2.0.1",
			Files:   []pkg.DpkgFileRecord{},
		},
		PURL: "a-purl-2",
		CPEs: []pkg.CPE{
			pkg.MustCPE("cpe:2.3:*:some:package:2:*:*:*:*:*:*:*"),
		},
	}

	catalog.Add(p1)
	catalog.Add(p2)

	s := sbom.SBOM{
		Artifacts: sbom.Artifacts{
			PackageCatalog: catalog,
			FileMetadata: map[source.Coordinates]source.FileMetadata{
				source.NewLocation("/a/place").Coordinates: {
					Mode:    0775,
					Type:    "directory",
					UserID:  0,
					GroupID: 0,
				},
				source.NewLocation("/a/place/a").Coordinates: {
					Mode:    0775,
					Type:    "regularFile",
					UserID:  0,
					GroupID: 0,
				},
				source.NewLocation("/b").Coordinates: {
					Mode:            0775,
					Type:            "symbolicLink",
					LinkDestination: "/c",
					UserID:          0,
					GroupID:         0,
				},
				source.NewLocation("/b/place/b").Coordinates: {
					Mode:    0644,
					Type:    "regularFile",
					UserID:  1,
					GroupID: 2,
				},
			},
			FileDigests: map[source.Coordinates][]file.Digest{
				source.NewLocation("/a/place/a").Coordinates: {
					{
						Algorithm: "sha256",
						Value:     "366a3f5653e34673b875891b021647440d0127c2ef041e3b1a22da2a7d4f3703",
					},
				},
				source.NewLocation("/b/place/b").Coordinates: {
					{
						Algorithm: "sha256",
						Value:     "1b3722da2a7d90d033b87581a2a3f12021647445653e34666ef041e3b4f3707c",
					},
				},
			},
			FileContents: map[source.Coordinates]string{
				source.NewLocation("/a/place/a").Coordinates: "the-contents",
			},
			LinuxDistribution: &linux.Release{
				ID:        "redhat",
				Version:   "7",
				VersionID: "7",
				IDLike: []string{
					"rhel",
				},
			},
		},
		Relationships: []artifact.Relationship{
			{
				From: p1,
				To:   p2,
				Type: artifact.OwnershipByFileOverlapRelationship,
				Data: map[string]string{
					"file": "path",
				},
			},
		},
		Source: source.Metadata{
			Scheme: source.ImageScheme,
			ImageMetadata: source.ImageMetadata{
				UserInput:      "user-image-input",
				ID:             "sha256:c2b46b4eb06296933b7cf0722683964e9ecbd93265b9ef6ae9642e3952afbba0",
				ManifestDigest: "sha256:2731251dc34951c0e50fcc643b4c5f74922dad1a5d98f302b504cf46cd5d9368",
				MediaType:      "application/vnd.docker.distribution.manifest.v2+json",
				Tags: []string{
					"stereoscope-fixture-image-simple:85066c51088bdd274f7a89e99e00490f666c49e72ffc955707cd6e18f0e22c5b",
				},
				Size: 38,
				Layers: []source.LayerMetadata{
					{
						MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip",
						Digest:    "sha256:3de16c5b8659a2e8d888b8ded8427be7a5686a3c8c4e4dd30de20f362827285b",
						Size:      22,
					},
					{
						MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip",
						Digest:    "sha256:366a3f5653e34673b875891b021647440d0127c2ef041e3b1a22da2a7d4f3703",
						Size:      16,
					},
				},
				RawManifest: []byte("eyJzY2hlbWFWZXJzaW9uIjoyLCJtZWRpYVR5cGUiOiJh..."),
				RawConfig:   []byte("eyJhcmNoaXRlY3R1cmUiOiJhbWQ2NCIsImNvbmZp..."),
				RepoDigests: []string{},
			},
		},
		Descriptor: sbom.Descriptor{
			Name:    "syft",
			Version: "v0.42.0-bogus",
			// the application configuration should be persisted here, however, we do not want to import
			// the application configuration in this package (it's reserved only for ingestion by the cmd package)
			Configuration: map[string]string{
				"config-key": "config-value",
			},
		},
	}

	testutils.AssertEncoderAgainstGoldenSnapshot(t,
		Format(),
		s,
		*updateJson,
	)
}
