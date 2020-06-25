package json

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

// TODO: add a JSON schema and write a test that validates output against the schema
// func validateAgainstV1Schema(t *testing.T, json string) {
// 	fullSchemaPath, err := filepath.Abs("v1-schema.json")
// 	if err != nil {
// 		t.Fatal("could not get path to schema:", err)
// 	}
// 	schemaLoader := gojsonschema.NewReferenceLoader(fmt.Sprintf("file://%s", fullSchemaPath))
// 	documentLoader := gojsonschema.NewStringLoader(json)

// 	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
// 	if err != nil {
// 		t.Fatal("unable to validate json schema:", err.Error())
// 	}

// 	if !result.Valid() {
// 		t.Errorf("failed json schema validation:")
// 		for _, desc := range result.Errors() {
// 			t.Errorf("  - %s\n", desc)
// 		}
// 	}
// }

func TestJsonPresenter(t *testing.T) {
	var buffer bytes.Buffer

	testImage := "image-simple"

	if *update {
		testutils.UpdateGoldenFixtureImage(t, testImage)
	}

	catalog := pkg.NewCatalog()
	img := testutils.GetGoldenFixtureImage(t, testImage)

	// populate catalog with test data
	catalog.Add(pkg.Package{
		Name:    "package-1",
		Version: "1.0.1",
		Source: []file.Reference{
			*img.SquashedTree().File("/somefile-1.txt"),
		},
		Type: pkg.DebPkg,
	})
	catalog.Add(pkg.Package{
		Name:    "package-2",
		Version: "2.0.1",
		Source: []file.Reference{
			*img.SquashedTree().File("/somefile-2.txt"),
		},
		Type: pkg.DebPkg,
	})

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

	// TODO: add me back in when there is a JSON schema
	// validateAgainstV1Schema(t, string(actual))
}
