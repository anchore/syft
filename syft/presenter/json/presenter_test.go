package json

import (
	"bytes"
	"flag"
	"testing"

	"github.com/anchore/go-testutils"
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/scope"
	"github.com/sergi/go-diff/diffmatchpatch"
)

var update = flag.Bool("update", false, "update the *.golden files for json presenters")

func TestJsonDirsPresenter(t *testing.T) {
	var buffer bytes.Buffer

	catalog := pkg.NewCatalog()

	// populate catalog with test data
	catalog.Add(pkg.Package{
		Name:    "package-1",
		Version: "1.0.1",
		Type:    pkg.PythonPkg,
		FoundBy: "the-cataloger-1",
		Source: []file.Reference{
			{Path: "/some/path/pkg1"},
		},
		Language:     pkg.Python,
		MetadataType: pkg.PythonPackageMetadataType,
		Licenses:     []string{"MIT"},
		Metadata: pkg.PythonPackageMetadata{
			Name:    "package-1",
			Version: "1.0.1",
		},
	})
	catalog.Add(pkg.Package{
		Name:    "package-2",
		Version: "2.0.1",
		Type:    pkg.DebPkg,
		FoundBy: "the-cataloger-2",
		Source: []file.Reference{
			{Path: "/some/path/pkg1"},
		},
		MetadataType: pkg.DpkgMetadataType,
		Metadata: pkg.DpkgMetadata{
			Package: "package-2",
			Version: "2.0.1",
		},
	})
	d := distro.NewUnknownDistro()
	s, err := scope.NewScopeFromDir("/some/path")
	if err != nil {
		t.Fatal(err)
	}
	pres := NewPresenter(catalog, s, d)

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
		diffs := dmp.DiffMain(string(actual), string(expected), true)
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

	// populate catalog with test data
	catalog.Add(pkg.Package{
		Name:    "package-1",
		Version: "1.0.1",
		Source: []file.Reference{
			*img.SquashedTree().File("/somefile-1.txt"),
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
	})
	catalog.Add(pkg.Package{
		Name:    "package-2",
		Version: "2.0.1",
		Source: []file.Reference{
			*img.SquashedTree().File("/somefile-2.txt"),
		},
		Type:         pkg.DebPkg,
		FoundBy:      "the-cataloger-2",
		MetadataType: pkg.DpkgMetadataType,
		Metadata: pkg.DpkgMetadata{
			Package: "package-2",
			Version: "2.0.1",
		},
	})

	s, err := scope.NewScopeFromImage(img, scope.AllLayersScope)
	d := distro.NewUnknownDistro()
	pres := NewPresenter(catalog, s, d)

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
		diffs := dmp.DiffMain(string(actual), string(expected), true)
		t.Errorf("mismatched output:\n%s", dmp.DiffPrettyText(diffs))
	}
}
