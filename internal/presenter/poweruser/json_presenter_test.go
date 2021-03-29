package poweruser

import (
	"bytes"
	"flag"
	"testing"

	"github.com/sergi/go-diff/diffmatchpatch"

	"github.com/anchore/syft/syft/file"

	"github.com/anchore/go-testutils"
	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

var updateJSONGoldenFiles = flag.Bool("update-json", false, "update the *.golden files for json presenters")

func must(c pkg.CPE, e error) pkg.CPE {
	if e != nil {
		panic(e)
	}
	return c
}

func TestJSONPresenter(t *testing.T) {
	var buffer bytes.Buffer

	catalog := pkg.NewCatalog()

	catalog.Add(pkg.Package{
		ID:      "package-1-id",
		Name:    "package-1",
		Version: "1.0.1",
		Locations: []source.Location{
			{
				RealPath: "/a/place/a",
			},
		},
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
			must(pkg.NewCPE("cpe:2.3:*:some:package:1:*:*:*:*:*:*:*")),
		},
	})
	catalog.Add(pkg.Package{
		ID:      "package-2-id",
		Name:    "package-2",
		Version: "2.0.1",
		Locations: []source.Location{
			{
				RealPath: "/b/place/b",
			},
		},
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
			must(pkg.NewCPE("cpe:2.3:*:some:package:2:*:*:*:*:*:*:*")),
		},
	})

	cfg := JSONDocumentConfig{
		ApplicationConfig: config.Application{
			FileMetadata: config.FileMetadata{
				Digests: []string{"sha256"},
			},
		},
		PackageCatalog: catalog,
		FileMetadata: map[source.Location]source.FileMetadata{
			source.NewLocation("/a/place"): {
				Mode:    0775,
				Type:    "directory",
				UserID:  0,
				GroupID: 0,
			},
			source.NewLocation("/a/place/a"): {
				Mode:    0775,
				Type:    "regularFile",
				UserID:  0,
				GroupID: 0,
			},
			source.NewLocation("/b"): {
				Mode:            0775,
				Type:            "symbolicLink",
				LinkDestination: "/c",
				UserID:          0,
				GroupID:         0,
			},
			source.NewLocation("/b/place/b"): {
				Mode:    0644,
				Type:    "regularFile",
				UserID:  1,
				GroupID: 2,
			},
		},
		FileDigests: map[source.Location][]file.Digest{
			source.NewLocation("/a/place/a"): {
				{
					Algorithm: "sha256",
					Value:     "366a3f5653e34673b875891b021647440d0127c2ef041e3b1a22da2a7d4f3703",
				},
			},
			source.NewLocation("/b/place/b"): {
				{
					Algorithm: "sha256",
					Value:     "1b3722da2a7d90d033b87581a2a3f12021647445653e34666ef041e3b4f3707c",
				},
			},
		},
		Distro: &distro.Distro{
			Type:       distro.RedHat,
			RawVersion: "7",
			IDLike:     "rhel",
		},
		SourceMetadata: source.Metadata{
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
	}

	if err := NewJSONPresenter(cfg).Present(&buffer); err != nil {
		t.Fatal(err)
	}
	actual := buffer.Bytes()

	if *updateJSONGoldenFiles {
		testutils.UpdateGoldenFileContents(t, actual)
	}

	expected := testutils.GetGoldenFileContents(t)

	if !bytes.Equal(expected, actual) {
		dmp := diffmatchpatch.New()
		diffs := dmp.DiffMain(string(expected), string(actual), true)
		t.Errorf("mismatched output:\n%s", dmp.DiffPrettyText(diffs))
	}
}
