package javascript

import (
	"os"
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/go-test/deep"
)

func TestParsePackageJSON(t *testing.T) {
	tests := []struct {
		Fixture     string
		ExpectedPkg pkg.Package
	}{
		{
			Fixture: "test-fixtures/pkg-json/package.json",
			ExpectedPkg: pkg.Package{
				Name:     "npm",
				Version:  "6.14.6",
				Type:     pkg.NpmPkg,
				Licenses: []string{"Artistic-2.0"},
				Language: pkg.JavaScript,
				Metadata: pkg.NpmMetadata{
					Author:   "Isaac Z. Schlueter <i@izs.me> (http://blog.izs.me)",
					Homepage: "https://docs.npmjs.com/",
				},
			},
		},
		{
			Fixture: "test-fixtures/pkg-json/package-nested-author.json",
			ExpectedPkg: pkg.Package{
				Name:     "npm",
				Version:  "6.14.6",
				Type:     pkg.NpmPkg,
				Licenses: []string{"Artistic-2.0"},
				Language: pkg.JavaScript,
				Metadata: pkg.NpmMetadata{
					Author:   "Isaac Z. Schlueter <i@izs.me> (http://blog.izs.me)",
					Homepage: "https://docs.npmjs.com/",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Fixture, func(t *testing.T) {
			fixture, err := os.Open(test.Fixture)
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

			for _, d := range deep.Equal(actual[0], test.ExpectedPkg) {

				t.Errorf("diff: %+v", d)
			}
		})
	}
}
