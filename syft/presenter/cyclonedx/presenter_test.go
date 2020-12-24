package cyclonedx

import (
	"bytes"
	"flag"
	"regexp"
	"testing"

	"github.com/anchore/stereoscope/pkg/imagetest"

	"github.com/anchore/go-testutils"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
	"github.com/sergi/go-diff/diffmatchpatch"
)

var update = flag.Bool("update", false, "update the *.golden files for json presenters")

func TestCycloneDxDirsPresenter(t *testing.T) {
	var buffer bytes.Buffer

	catalog := pkg.NewCatalog()

	// populate catalog with test data
	catalog.Add(pkg.Package{
		Name:    "package1",
		Version: "1.0.1",
		Type:    pkg.DebPkg,
		FoundBy: "the-cataloger-1",
		Locations: []source.Location{
			{Path: "/some/path/pkg1"},
		},
		Metadata: pkg.DpkgMetadata{
			Package:      "package1",
			Version:      "1.0.1",
			Architecture: "amd64",
		},
	})
	catalog.Add(pkg.Package{
		Name:    "package2",
		Version: "2.0.1",
		Type:    pkg.DebPkg,
		FoundBy: "the-cataloger-2",
		Locations: []source.Location{
			{Path: "/some/path/pkg1"},
		},
		Licenses: []string{
			"MIT",
			"Apache-v2",
		},
		Metadata: pkg.DpkgMetadata{
			Package:      "package2",
			Version:      "1.0.2",
			Architecture: "amd64",
		},
	})

	s, err := source.NewFromDirectory("/some/path")
	if err != nil {
		t.Fatal(err)
	}

	pres := NewPresenter(catalog, s.Metadata)

	// run presenter
	err = pres.Present(&buffer)
	if err != nil {
		t.Fatal(err)
	}
	actual := buffer.Bytes()

	if *update {
		testutils.UpdateGoldenFileContents(t, actual)
	}

	var expected = testutils.GetGoldenFileContents(t)

	// remove dynamic values, which are tested independently
	actual = redact(actual)
	expected = redact(expected)

	if !bytes.Equal(expected, actual) {
		dmp := diffmatchpatch.New()
		diffs := dmp.DiffMain(string(actual), string(expected), true)
		t.Errorf("mismatched output:\n%s", dmp.DiffPrettyText(diffs))
	}

}

func TestCycloneDxImgsPresenter(t *testing.T) {
	var buffer bytes.Buffer

	catalog := pkg.NewCatalog()
	img, cleanup := imagetest.GetFixtureImage(t, "docker-archive", "image-simple")
	defer cleanup()

	_, _, ref1, _ := img.SquashedTree().File("/somefile-1.txt", true)
	_, _, ref2, _ := img.SquashedTree().File("/somefile-2.txt", true)

	// populate catalog with test data
	catalog.Add(pkg.Package{
		Name:    "package1",
		Version: "1.0.1",
		Locations: []source.Location{
			source.NewLocationFromImage(*ref1, img),
		},
		Type:    pkg.RpmPkg,
		FoundBy: "the-cataloger-1",
		PURL:    "the-purl-1",
	})
	catalog.Add(pkg.Package{
		Name:    "package2",
		Version: "2.0.1",
		Locations: []source.Location{
			source.NewLocationFromImage(*ref2, img),
		},
		Type:    pkg.RpmPkg,
		FoundBy: "the-cataloger-2",
		Licenses: []string{
			"MIT",
			"Apache-v2",
		},
		PURL: "the-purl-2",
	})

	s, err := source.NewFromImage(img, source.SquashedScope, "user-image-input")
	if err != nil {
		t.Fatal(err)
	}

	// This accounts for the non-deterministic digest value that we end up with when
	// we build a container image dynamically during testing. Ultimately, we should
	// use a golden image as a test fixture in place of building this image during
	// testing. At that time, this line will no longer be necessary.
	//
	// This value is sourced from the "version" node in "./test-fixtures/snapshot/TestCycloneDxImgsPresenter.golden"
	s.Metadata.ImageMetadata.ManifestDigest = "sha256:2731251dc34951c0e50fcc643b4c5f74922dad1a5d98f302b504cf46cd5d9368"

	pres := NewPresenter(catalog, s.Metadata)

	// run presenter
	err = pres.Present(&buffer)
	if err != nil {
		t.Fatal(err)
	}
	actual := buffer.Bytes()

	if *update {
		testutils.UpdateGoldenFileContents(t, actual)
	}

	var expected = testutils.GetGoldenFileContents(t)

	// remove dynamic values, which are tested independently
	actual = redact(actual)
	expected = redact(expected)

	if !bytes.Equal(expected, actual) {
		dmp := diffmatchpatch.New()
		diffs := dmp.DiffMain(string(expected), string(actual), true)
		t.Errorf("mismatched output:\n%s", dmp.DiffPrettyText(diffs))
	}
}

func redact(s []byte) []byte {
	serialPattern := regexp.MustCompile(`serialNumber="[a-zA-Z0-9\-:]+"`)
	rfc3339Pattern := regexp.MustCompile(`([0-9]+)-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])[Tt]([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|60)(\.[0-9]+)?(([Zz])|([\+|\-]([01][0-9]|2[0-3]):[0-5][0-9]))`)

	for _, pattern := range []*regexp.Regexp{serialPattern, rfc3339Pattern} {
		s = pattern.ReplaceAll(s, []byte("redacted"))
	}
	return s
}
