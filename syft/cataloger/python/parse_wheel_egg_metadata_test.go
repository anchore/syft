package python

import (
	"os"
	"testing"

	"github.com/anchore/stereoscope/pkg/file"

	"github.com/anchore/syft/syft/pkg"
	"github.com/go-test/deep"
)

func TestParseWheelEggMetadata(t *testing.T) {
	tests := []struct {
		Fixture          string
		ExpectedMetadata pkg.PythonPackageMetadata
	}{
		{
			Fixture: "test-fixtures/egg-info/PKG-INFO",
			ExpectedMetadata: pkg.PythonPackageMetadata{
				Name:                 "requests",
				Version:              "2.22.0",
				License:              "Apache 2.0",
				Platform:             "UNKNOWN",
				Author:               "Kenneth Reitz",
				AuthorEmail:          "me@kennethreitz.org",
				SitePackagesRootPath: "test-fixtures",
			},
		},
		{
			Fixture: "test-fixtures/dist-info/METADATA",
			ExpectedMetadata: pkg.PythonPackageMetadata{
				Name:                 "Pygments",
				Version:              "2.6.1",
				License:              "BSD License",
				Platform:             "any",
				Author:               "Georg Brandl",
				AuthorEmail:          "georg@python.org",
				SitePackagesRootPath: "test-fixtures",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Fixture, func(t *testing.T) {
			fixture, err := os.Open(test.Fixture)
			if err != nil {
				t.Fatalf("failed to open fixture: %+v", err)
			}

			actual, err := parseWheelOrEggMetadata(file.Path(test.Fixture), fixture)
			if err != nil {
				t.Fatalf("failed to parse: %+v", err)
			}

			for _, d := range deep.Equal(actual, test.ExpectedMetadata) {
				t.Errorf("diff: %+v", d)
			}
		})
	}

}
