package testutil

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source/stereoscopesource"
)

func ImageInput(t testing.TB, testImage string, options ...ImageOption) sbom.SBOM {
	t.Helper()
	catalog := pkg.NewCollection()
	var cfg imageCfg
	var img *image.Image
	for _, opt := range options {
		opt(&cfg)
	}

	defer changeToDirectoryWithGoldenFixture(t, testImage)()

	switch cfg.fromSnapshot {
	case true:
		img = imagetest.GetGoldenFixtureImage(t, testImage)
	default:
		img = imagetest.GetFixtureImage(t, "docker-archive", testImage)
	}

	populateImageCatalog(catalog, img)

	// this is a hard coded value that is not given by the fixture helper and must be provided manually
	img.Metadata.ManifestDigest = "sha256:2731251dc34951c0e50fcc643b4c5f74922dad1a5d98f302b504cf46cd5d9368"

	src := stereoscopesource.New(img, stereoscopesource.ImageConfig{
		Reference: "user-image-input",
	})

	return sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages: catalog,
			LinuxDistribution: &linux.Release{
				PrettyName: "debian",
				Name:       "debian",
				ID:         "debian",
				IDLike:     []string{"like!"},
				Version:    "1.2.3",
				VersionID:  "1.2.3",
			},
		},
		Source: src.Describe(),
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
}

func changeToDirectoryWithGoldenFixture(t testing.TB, testImage string) func() {
	// check if test fixture exists... if not, check if there is a shared fixture relative to this dir
	fn := func() {}

	path := filepath.Join("test-fixtures", testImage)
	if _, err := os.Stat(path); err != nil {
		// change dir, restore as defer
		wd, err := os.Getwd()
		require.NoError(t, err)
		fn = func() {
			require.NoError(t, os.Chdir(wd))
		}

		// change dir to the testutil dir
		require.NoError(t, os.Chdir(filepath.Join(wd, "..", "internal", "testutil")))
		t.Cleanup(fn)

		if _, err := os.Stat(path); err != nil {
			t.Fatalf("unable to find test fixture: %s", path)
		}
	}
	return fn
}

func populateImageCatalog(catalog *pkg.Collection, img *image.Image) {
	// TODO: this helper function is coupled to the image-simple fixture, which seems like a bad idea
	_, ref1, _ := img.SquashedTree().File("/somefile-1.txt", filetree.FollowBasenameLinks)
	_, ref2, _ := img.SquashedTree().File("/somefile-2.txt", filetree.FollowBasenameLinks)

	// populate catalog with test data
	if ref1 != nil {
		catalog.Add(pkg.Package{
			Name:    "package-1",
			Version: "1.0.1",
			Locations: file.NewLocationSet(
				file.NewLocationFromImage(string(ref1.RealPath), *ref1.Reference, img),
			),
			Type:     pkg.PythonPkg,
			FoundBy:  "the-cataloger-1",
			Language: pkg.Python,
			Licenses: pkg.NewLicenseSet(
				pkg.NewLicense("MIT"),
			),
			Metadata: pkg.PythonPackage{
				Name:    "package-1",
				Version: "1.0.1",
			},
			PURL: "a-purl-1", // intentionally a bad pURL for test fixtures
			CPEs: []cpe.CPE{
				cpe.Must("cpe:2.3:*:some:package:1:*:*:*:*:*:*:*", cpe.GeneratedSource),
			},
		})
	}

	if ref2 != nil {
		catalog.Add(pkg.Package{
			Name:    "package-2",
			Version: "2.0.1",
			Locations: file.NewLocationSet(
				file.NewLocationFromImage(string(ref2.RealPath), *ref2.Reference, img),
			),
			Type:    pkg.DebPkg,
			FoundBy: "the-cataloger-2",
			Metadata: pkg.DpkgDBEntry{
				Package: "package-2",
				Version: "2.0.1",
			},
			PURL: "pkg:deb/debian/package-2@2.0.1",
			CPEs: []cpe.CPE{
				cpe.Must("cpe:2.3:*:some:package:2:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
			},
		})
	}
}
