package testutils

import (
	"bytes"
	"strings"
	"testing"

	"github.com/anchore/go-testutils"
	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/sergi/go-diff/diffmatchpatch"
	"github.com/stretchr/testify/assert"
)

type redactor func(s []byte) []byte

type imageCfg struct {
	fromSnapshot bool
}

type ImageOption func(cfg *imageCfg)

func FromSnapshot() ImageOption {
	return func(cfg *imageCfg) {
		cfg.fromSnapshot = true
	}
}

func AssertEncoderAgainstGoldenImageSnapshot(t *testing.T, format sbom.Format, sbom sbom.SBOM, testImage string, updateSnapshot bool, redactors ...redactor) {
	var buffer bytes.Buffer

	// grab the latest image contents and persist
	if updateSnapshot {
		imagetest.UpdateGoldenFixtureImage(t, testImage)
	}

	err := format.Encode(&buffer, sbom)
	assert.NoError(t, err)
	actual := buffer.Bytes()

	// replace the expected snapshot contents with the current encoder contents
	if updateSnapshot {
		testutils.UpdateGoldenFileContents(t, actual)
	}

	var expected = testutils.GetGoldenFileContents(t)

	// remove dynamic values, which should be tested independently
	redactors = append(redactors, carriageRedactor)
	for _, r := range redactors {
		actual = r(actual)
		expected = r(expected)
	}

	// assert that the golden file snapshot matches the actual contents
	if !bytes.Equal(expected, actual) {
		dmp := diffmatchpatch.New()
		diffs := dmp.DiffMain(string(expected), string(actual), true)
		t.Errorf("mismatched output:\n%s", dmp.DiffPrettyText(diffs))
	}
}

func AssertEncoderAgainstGoldenSnapshot(t *testing.T, format sbom.Format, sbom sbom.SBOM, updateSnapshot bool, redactors ...redactor) {
	var buffer bytes.Buffer

	err := format.Encode(&buffer, sbom)
	assert.NoError(t, err)
	actual := buffer.Bytes()

	// replace the expected snapshot contents with the current encoder contents
	if updateSnapshot {
		testutils.UpdateGoldenFileContents(t, actual)
	}

	var expected = testutils.GetGoldenFileContents(t)

	// remove dynamic values, which should be tested independently
	redactors = append(redactors, carriageRedactor)
	for _, r := range redactors {
		actual = r(actual)
		expected = r(expected)
	}

	if !bytes.Equal(expected, actual) {
		dmp := diffmatchpatch.New()
		diffs := dmp.DiffMain(string(expected), string(actual), true)
		t.Logf("len: %d\nexpected: %s", len(expected), expected)
		t.Logf("len: %d\nactual: %s", len(actual), actual)
		t.Errorf("mismatched output:\n%s", dmp.DiffPrettyText(diffs))
	}
}

func ImageInput(t testing.TB, testImage string, options ...ImageOption) sbom.SBOM {
	t.Helper()
	catalog := pkg.NewCatalog()
	var cfg imageCfg
	var img *image.Image
	for _, opt := range options {
		opt(&cfg)
	}

	switch cfg.fromSnapshot {
	case true:
		img = imagetest.GetGoldenFixtureImage(t, testImage)
	default:
		img = imagetest.GetFixtureImage(t, "docker-archive", testImage)
	}

	populateImageCatalog(catalog, img)

	// this is a hard coded value that is not given by the fixture helper and must be provided manually
	img.Metadata.ManifestDigest = "sha256:2731251dc34951c0e50fcc643b4c5f74922dad1a5d98f302b504cf46cd5d9368"

	src, err := source.NewFromImage(img, "user-image-input")
	assert.NoError(t, err)

	return sbom.SBOM{
		Artifacts: sbom.Artifacts{
			PackageCatalog: catalog,
			LinuxDistribution: &linux.Release{
				PrettyName: "debian",
				Name:       "debian",
				ID:         "debian",
				IDLike:     []string{"like!"},
				Version:    "1.2.3",
				VersionID:  "1.2.3",
			},
		},
		Source: src.Metadata,
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

func carriageRedactor(s []byte) []byte {
	msg := strings.ReplaceAll(string(s), "\r\n", "\n")
	return []byte(msg)
}

func populateImageCatalog(catalog *pkg.Catalog, img *image.Image) {
	_, ref1, _ := img.SquashedTree().File("/somefile-1.txt", filetree.FollowBasenameLinks)
	_, ref2, _ := img.SquashedTree().File("/somefile-2.txt", filetree.FollowBasenameLinks)

	// populate catalog with test data
	catalog.Add(pkg.Package{
		Name:    "package-1",
		Version: "1.0.1",
		Locations: source.NewLocationSet(
			source.NewLocationFromImage(string(ref1.RealPath), *ref1, img),
		),
		Type:         pkg.PythonPkg,
		FoundBy:      "the-cataloger-1",
		Language:     pkg.Python,
		MetadataType: pkg.PythonPackageMetadataType,
		Licenses:     []string{"MIT"},
		Metadata: pkg.PythonPackageMetadata{
			Name:    "package-1",
			Version: "1.0.1",
		},
		PURL: "a-purl-1", // intentionally a bad pURL for test fixtures
		CPEs: []pkg.CPE{
			pkg.MustCPE("cpe:2.3:*:some:package:1:*:*:*:*:*:*:*"),
		},
	})
	catalog.Add(pkg.Package{
		Name:    "package-2",
		Version: "2.0.1",
		Locations: source.NewLocationSet(
			source.NewLocationFromImage(string(ref2.RealPath), *ref2, img),
		),
		Type:         pkg.DebPkg,
		FoundBy:      "the-cataloger-2",
		MetadataType: pkg.DpkgMetadataType,
		Metadata: pkg.DpkgMetadata{
			Package: "package-2",
			Version: "2.0.1",
		},
		PURL: "pkg:deb/debian/package-2@2.0.1",
		CPEs: []pkg.CPE{
			pkg.MustCPE("cpe:2.3:*:some:package:2:*:*:*:*:*:*:*"),
		},
	})
}

func DirectoryInput(t testing.TB) sbom.SBOM {
	catalog := newDirectoryCatalog()

	src, err := source.NewFromDirectory("/some/path")
	assert.NoError(t, err)

	return sbom.SBOM{
		Artifacts: sbom.Artifacts{
			PackageCatalog: catalog,
			LinuxDistribution: &linux.Release{
				PrettyName: "debian",
				Name:       "debian",
				ID:         "debian",
				IDLike:     []string{"like!"},
				Version:    "1.2.3",
				VersionID:  "1.2.3",
			},
		},
		Source: src.Metadata,
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

func newDirectoryCatalog() *pkg.Catalog {
	catalog := pkg.NewCatalog()

	// populate catalog with test data
	catalog.Add(pkg.Package{
		Name:    "package-1",
		Version: "1.0.1",
		Type:    pkg.PythonPkg,
		FoundBy: "the-cataloger-1",
		Locations: source.NewLocationSet(
			source.NewLocation("/some/path/pkg1"),
		),
		Language:     pkg.Python,
		MetadataType: pkg.PythonPackageMetadataType,
		Licenses:     []string{"MIT"},
		Metadata: pkg.PythonPackageMetadata{
			Name:    "package-1",
			Version: "1.0.1",
			Files: []pkg.PythonFileRecord{
				{
					Path: "/some/path/pkg1/dependencies/foo",
				},
			},
		},
		PURL: "a-purl-2", // intentionally a bad pURL for test fixtures
		CPEs: []pkg.CPE{
			pkg.MustCPE("cpe:2.3:*:some:package:2:*:*:*:*:*:*:*"),
		},
	})
	catalog.Add(pkg.Package{
		Name:    "package-2",
		Version: "2.0.1",
		Type:    pkg.DebPkg,
		FoundBy: "the-cataloger-2",
		Locations: source.NewLocationSet(
			source.NewLocation("/some/path/pkg1"),
		),
		MetadataType: pkg.DpkgMetadataType,
		Metadata: pkg.DpkgMetadata{
			Package: "package-2",
			Version: "2.0.1",
		},
		PURL: "pkg:deb/debian/package-2@2.0.1",
		CPEs: []pkg.CPE{
			pkg.MustCPE("cpe:2.3:*:some:package:2:*:*:*:*:*:*:*"),
		},
	})

	return catalog
}
