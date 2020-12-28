package json

import (
	"bytes"
	"flag"
	"testing"

	"github.com/anchore/stereoscope/pkg/filetree"

	"github.com/anchore/go-testutils"
	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
	"github.com/sergi/go-diff/diffmatchpatch"
)

var update = flag.Bool("update", false, "update the *.golden files for json presenters")

func must(c pkg.CPE, e error) pkg.CPE {
	if e != nil {
		panic(e)
	}
	return c
}

func TestJsonDirsPresenter(t *testing.T) {
	var buffer bytes.Buffer

	catalog := pkg.NewCatalog()

	// populate catalog with test data
	catalog.Add(pkg.Package{
		Name:    "package-1",
		Version: "1.0.1",
		Type:    pkg.PythonPkg,
		FoundBy: "the-cataloger-1",
		Locations: []source.Location{
			{Path: "/some/path/pkg1"},
		},
		Language:     pkg.Python,
		MetadataType: pkg.PythonPackageMetadataType,
		Licenses:     []string{"MIT"},
		Metadata: pkg.PythonPackageMetadata{
			Name:    "package-1",
			Version: "1.0.1",
		},
		PURL: "a-purl-2",
		CPEs: []pkg.CPE{
			must(pkg.NewCPE("cpe:2.3:*:some:package:2:*:*:*:*:*:*:*")),
		},
	})
	catalog.Add(pkg.Package{
		Name:    "package-2",
		Version: "2.0.1",
		Type:    pkg.DebPkg,
		FoundBy: "the-cataloger-2",
		Locations: []source.Location{
			{Path: "/some/path/pkg1"},
		},
		MetadataType: pkg.DpkgMetadataType,
		Metadata: pkg.DpkgMetadata{
			Package: "package-2",
			Version: "2.0.1",
		},
		PURL: "a-purl-2",
		CPEs: []pkg.CPE{
			must(pkg.NewCPE("cpe:2.3:*:some:package:2:*:*:*:*:*:*:*")),
		},
	})
	var d *distro.Distro
	s, err := source.NewFromDirectory("/some/path")
	if err != nil {
		t.Fatal(err)
	}
	pres := NewPresenter(catalog, s.Metadata, d)

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

	if !bytes.Equal(expected, actual) {
		dmp := diffmatchpatch.New()
		diffs := dmp.DiffMain(string(expected), string(actual), true)
		t.Errorf("mismatched output:\n%s", dmp.DiffPrettyText(diffs))
	}

}

func TestJsonImgsPresenter(t *testing.T) {
	var buffer bytes.Buffer

	testImage := "image-simple"

	if *update {
		imagetest.UpdateGoldenFixtureImage(t, testImage)
	}

	catalog := pkg.NewCatalog()
	img := imagetest.GetGoldenFixtureImage(t, testImage)

	_, _, ref1, _ := img.SquashedTree().File("/somefile-1.txt", filetree.FollowBasenameLinks)
	_, _, ref2, _ := img.SquashedTree().File("/somefile-2.txt", filetree.FollowBasenameLinks)

	// populate catalog with test data
	catalog.Add(pkg.Package{
		Name:    "package-1",
		Version: "1.0.1",
		Locations: []source.Location{
			source.NewLocationFromImage(*ref1, img),
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
			must(pkg.NewCPE("cpe:2.3:*:some:package:1:*:*:*:*:*:*:*")),
		},
	})
	catalog.Add(pkg.Package{
		Name:    "package-2",
		Version: "2.0.1",
		Locations: []source.Location{
			source.NewLocationFromImage(*ref2, img),
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
			must(pkg.NewCPE("cpe:2.3:*:some:package:2:*:*:*:*:*:*:*")),
		},
	})

	// this is a hard coded value that is not given by the fixture helper and must be provided manually
	img.Metadata.ManifestDigest = "sha256:2731251dc34951c0e50fcc643b4c5f74922dad1a5d98f302b504cf46cd5d9368"

	s, err := source.NewFromImage(img, source.SquashedScope, "user-image-input")
	var d *distro.Distro
	pres := NewPresenter(catalog, s.Metadata, d)

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

	if !bytes.Equal(expected, actual) {
		dmp := diffmatchpatch.New()
		diffs := dmp.DiffMain(string(expected), string(actual), true)
		t.Errorf("mismatched output:\n%s", dmp.DiffPrettyText(diffs))
	}
}
