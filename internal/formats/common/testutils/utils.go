package testutils

import (
	"bytes"
	"testing"

	"github.com/anchore/syft/syft/presenter"

	"github.com/anchore/go-testutils"
	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
	"github.com/sergi/go-diff/diffmatchpatch"
	"github.com/stretchr/testify/assert"
)

type redactor func(s []byte) []byte

func MustCPE(c pkg.CPE, e error) pkg.CPE {
	if e != nil {
		panic(e)
	}
	return c
}

func AssertPresenterAgainstGoldenImageSnapshot(t *testing.T, pres presenter.Presenter, testImage string, updateSnapshot bool, redactors ...redactor) {
	var buffer bytes.Buffer

	// grab the latest image contents and persist
	if updateSnapshot {
		imagetest.UpdateGoldenFixtureImage(t, testImage)
	}

	err := pres.Present(&buffer)
	assert.NoError(t, err)
	actual := buffer.Bytes()

	// replace the expected snapshot contents with the current presenter contents
	if updateSnapshot {
		testutils.UpdateGoldenFileContents(t, actual)
	}

	var expected = testutils.GetGoldenFileContents(t)

	// remove dynamic values, which should be tested independently
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

func AssertPresenterAgainstGoldenSnapshot(t *testing.T, pres presenter.Presenter, updateSnapshot bool, redactors ...redactor) {
	var buffer bytes.Buffer

	err := pres.Present(&buffer)
	assert.NoError(t, err)
	actual := buffer.Bytes()

	// replace the expected snapshot contents with the current presenter contents
	if updateSnapshot {
		testutils.UpdateGoldenFileContents(t, actual)
	}

	var expected = testutils.GetGoldenFileContents(t)

	// remove dynamic values, which should be tested independently
	for _, r := range redactors {
		actual = r(actual)
		expected = r(expected)
	}

	if !bytes.Equal(expected, actual) {
		dmp := diffmatchpatch.New()
		diffs := dmp.DiffMain(string(expected), string(actual), true)
		t.Errorf("mismatched output:\n%s", dmp.DiffPrettyText(diffs))
	}
}

func ImageInput(t testing.TB, testImage string) (*pkg.Catalog, source.Metadata, *distro.Distro) {
	t.Helper()
	catalog := pkg.NewCatalog()
	img := imagetest.GetGoldenFixtureImage(t, testImage)

	_, ref1, _ := img.SquashedTree().File("/somefile-1.txt", filetree.FollowBasenameLinks)
	_, ref2, _ := img.SquashedTree().File("/somefile-2.txt", filetree.FollowBasenameLinks)

	// populate catalog with test data
	catalog.Add(pkg.Package{
		ID:      "package-1-id",
		Name:    "package-1",
		Version: "1.0.1",
		Locations: []source.Location{
			source.NewLocationFromImage(string(ref1.RealPath), *ref1, img),
		},
		Type:         pkg.PythonPkg,
		FoundBy:      "the-cataloger-1",
		Language:     pkg.Python,
		MetadataType: pkg.PythonPackageMetadataType,
		Licenses:     []string{"MIT"},
		Metadata: pkg.PythonPackageMetadata{
			Name:    "package-1",
			Version: "1.0.1",
		},
		PURL: "a-purl-1",
		CPEs: []pkg.CPE{
			MustCPE(pkg.NewCPE("cpe:2.3:*:some:package:1:*:*:*:*:*:*:*")),
		},
	})
	catalog.Add(pkg.Package{
		ID:      "package-2-id",
		Name:    "package-2",
		Version: "2.0.1",
		Locations: []source.Location{
			source.NewLocationFromImage(string(ref2.RealPath), *ref2, img),
		},
		Type:         pkg.DebPkg,
		FoundBy:      "the-cataloger-2",
		MetadataType: pkg.DpkgMetadataType,
		Metadata: pkg.DpkgMetadata{
			Package: "package-2",
			Version: "2.0.1",
		},
		PURL: "a-purl-2",
		CPEs: []pkg.CPE{
			MustCPE(pkg.NewCPE("cpe:2.3:*:some:package:2:*:*:*:*:*:*:*")),
		},
	})

	// this is a hard coded value that is not given by the fixture helper and must be provided manually
	img.Metadata.ManifestDigest = "sha256:2731251dc34951c0e50fcc643b4c5f74922dad1a5d98f302b504cf46cd5d9368"

	src, err := source.NewFromImage(img, "user-image-input")
	assert.NoError(t, err)

	dist, err := distro.NewDistro(distro.Debian, "1.2.3", "like!")
	assert.NoError(t, err)

	return catalog, src.Metadata, &dist
}

func DirectoryInput(t testing.TB) (*pkg.Catalog, source.Metadata, *distro.Distro) {
	catalog := pkg.NewCatalog()

	// populate catalog with test data
	catalog.Add(pkg.Package{
		ID:      "package-1-id",
		Name:    "package-1",
		Version: "1.0.1",
		Type:    pkg.PythonPkg,
		FoundBy: "the-cataloger-1",
		Locations: []source.Location{
			{RealPath: "/some/path/pkg1"},
		},
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
		PURL: "a-purl-2",
		CPEs: []pkg.CPE{
			MustCPE(pkg.NewCPE("cpe:2.3:*:some:package:2:*:*:*:*:*:*:*")),
		},
	})
	catalog.Add(pkg.Package{
		ID:      "package-2-id",
		Name:    "package-2",
		Version: "2.0.1",
		Type:    pkg.DebPkg,
		FoundBy: "the-cataloger-2",
		Locations: []source.Location{
			{RealPath: "/some/path/pkg1"},
		},
		MetadataType: pkg.DpkgMetadataType,
		Metadata: pkg.DpkgMetadata{
			Package: "package-2",
			Version: "2.0.1",
		},
		PURL: "a-purl-2",
		CPEs: []pkg.CPE{
			MustCPE(pkg.NewCPE("cpe:2.3:*:some:package:2:*:*:*:*:*:*:*")),
		},
	})

	dist, err := distro.NewDistro(distro.Debian, "1.2.3", "like!")
	assert.NoError(t, err)

	src, err := source.NewFromDirectory("/some/path")
	assert.NoError(t, err)

	return catalog, src.Metadata, &dist
}
