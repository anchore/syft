package python

import (
	"os"
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/go-test/deep"
)

func TestPythonPackageCataloger(t *testing.T) {
	tests := []struct {
		Fixture          string
		ExpectedMetadata []pkg.Package
	}{
		{
			Fixture: "test-fixtures/",
			ExpectedMetadata: []pkg.Package{
				{
					Name:         "requests",
					Version:      "2.22.0",
					Type:         pkg.PythonPkg,
					Language:     pkg.Python,
					Licenses:     []string{"Apache 2.0"},
					MetadataType: pkg.PythonEggWheelMetadataType,
					Metadata: pkg.EggWheelMetadata{
						Name:        "requests",
						Version:     "2.22.0",
						License:     "Apache 2.0",
						Platform:    "UNKNOWN",
						Author:      "Kenneth Reitz",
						AuthorEmail: "me@kennethreitz.org",
					},
				},
				{
					Name:         "Pygments",
					Version:      "2.6.1",
					Type:         pkg.PythonPkg,
					Language:     pkg.Python,
					Licenses:     []string{"BSD License"},
					MetadataType: pkg.PythonEggWheelMetadataType,
					Metadata: pkg.EggWheelMetadata{
						Name:        "Pygments",
						Version:     "2.6.1",
						License:     "BSD License",
						Platform:    "any",
						Author:      "Georg Brandl",
						AuthorEmail: "georg@python.org",
					},
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

			actual, err := parseWheelOrEggMetadata(fixture.Name(), fixture)
			if err != nil {
				t.Fatalf("failed to parse python package: %+v", err)
			}

			for _, d := range deep.Equal(actual, &test.ExpectedMetadata) {
				t.Errorf("diff: %+v", d)
			}
		})
	}

}
