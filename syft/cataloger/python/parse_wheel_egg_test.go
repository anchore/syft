package python

import (
	"os"
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/go-test/deep"
)

func TestParseEggMetadata(t *testing.T) {
	tests := []struct {
		Fixture          string
		ExpectedMetadata pkg.EggWheelMetadata
	}{
		{
			Fixture: "test-fixtures/egg-info/PKG-INFO",
			ExpectedMetadata: pkg.EggWheelMetadata{
				Name:        "requests",
				Version:     "2.22.0",
				License:     "Apache 2.0",
				Platform:    "UNKNOWN",
				Author:      "Kenneth Reitz",
				AuthorEmail: "me@kennethreitz.org",
			},
		},
		{
			Fixture: "test-fixtures/dist-info/METADATA",
			ExpectedMetadata: pkg.EggWheelMetadata{
				Name:        "Pygments",
				Version:     "2.6.1",
				License:     "BSD License",
				Platform:    "any",
				Author:      "Georg Brandl",
				AuthorEmail: "georg@python.org",
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
				t.Fatalf("failed to parse egg-info: %+v", err)
			}

			for _, d := range deep.Equal(actual, &test.ExpectedMetadata) {
				t.Errorf("diff: %+v", d)
			}
		})
	}

}
