package imgs

import (
	"bytes"
	"flag"
	"testing"

	"github.com/anchore/go-testutils"
	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/sergi/go-diff/diffmatchpatch"
)

var update = flag.Bool("update", false, "update the *.golden files for json presenters")

type PackageInfo struct {
	Name    string
	Version string
}

func TestTextPresenter(t *testing.T) {
	var buffer bytes.Buffer

	catalog := pkg.NewCatalog()
	img, cleanup := testutils.GetFixtureImage(t, "docker-archive", "image-simple")
	defer cleanup()

	// populate catalog with test data
	catalog.Add(pkg.Package{
		Name:    "package-1",
		Version: "1.0.1",
		Source: []file.Reference{
			*img.SquashedTree().File("/somefile-1.txt"),
		},
		FoundBy: "dpkg",
		Type:    pkg.DebPkg,
	})
	catalog.Add(pkg.Package{
		Name:    "package-2",
		Version: "2.0.1",
		Source: []file.Reference{
			*img.SquashedTree().File("/somefile-2.txt"),
		},
		FoundBy:  "dpkg",
		Metadata: PackageInfo{Name: "package-2", Version: "1.0.2"},
		Type:     pkg.DebPkg,
	})

	// stub out all the digests so that they don't affect tests comparisons
	// TODO: update with go-testutils feature when issue #1 is resolved
	for _, l := range img.Layers {
		l.Metadata.Digest = "sha256:ad8ecdc058976c07e7e347cb89fa9ad86a294b5ceaae6d09713fb035f84115abf3c4a2388a4af3aa60f13b94f4c6846930bdf53"
	}

	pres := NewPresenter(img, catalog)
	// run presenter
	err := pres.Present(&buffer)
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
