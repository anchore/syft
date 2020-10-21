package javascript

import (
	"os"
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/go-test/deep"
)

func TestParsePackageJSON(t *testing.T) {
	expected := pkg.Package{
		Name:     "npm",
		Version:  "6.14.6",
		Type:     pkg.NpmPkg,
		Licenses: []string{"Artistic-2.0"},
		Language: pkg.JavaScript,
		Metadata: pkg.NpmPackageJsonMetadata{
			Author:   "Isaac Z. Schlueter <i@izs.me> (http://blog.izs.me)",
			Homepage: "https://docs.npmjs.com/",
		},
	}
	fixture, err := os.Open("test-fixtures/pkg-json/package.json")
	if err != nil {
		t.Fatalf("failed to open fixture: %+v", err)
	}

	actual, err := parsePackageJSON(fixture.Name(), fixture)
	if err != nil {
		t.Fatalf("failed to parse package-lock.json: %+v", err)
	}
	if len(actual) != 1 {
		for _, a := range actual {
			t.Log("   ", a)
		}
		t.Fatalf("unexpected package count: %d!=1", len(actual))
	}

	for _, d := range deep.Equal(actual[0], expected) {
		t.Errorf("diff: %+v", d)
	}

}
