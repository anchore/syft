package python

import (
	"os"
	"testing"

	"github.com/anchore/syft/syft/pkg"
)

func assertPkgsEqual(t *testing.T, actual []pkg.Package, expected map[string]pkg.Package) {
	t.Helper()
	if len(actual) != len(expected) {
		for _, a := range actual {
			t.Log("   ", a)
		}
		t.Fatalf("unexpected package count: %d!=%d", len(actual), len(expected))
	}

	for _, a := range actual {
		expectedPkg, ok := expected[a.Name]
		if !ok {
			t.Errorf("unexpected package found: '%s'", a.Name)
		}

		if expectedPkg.Version != a.Version {
			t.Errorf("unexpected package version: '%s'", a.Version)
		}

		if a.Language != expectedPkg.Language {
			t.Errorf("bad language: '%+v'", a.Language)
		}

		if a.Type != expectedPkg.Type {
			t.Errorf("bad package type: %+v", a.Type)
		}

		if len(a.Licenses) < len(expectedPkg.Licenses) {
			t.Errorf("bad package licenses count: '%+v'", a.Licenses)
		}
		if len(a.Licenses) > 0 {
			if a.Licenses[0] != expectedPkg.Licenses[0] {
				t.Errorf("bad package licenses: '%+v'", a.Licenses)
			}
		}

	}
}

func TestParseEggMetadata(t *testing.T) {
	expected := map[string]pkg.Package{
		"requests": {
			Name:     "requests",
			Version:  "2.22.0",
			Language: pkg.Python,
			Type:     pkg.PythonPkg,
			Licenses: []string{"Apache 2.0"},
		},
	}
	fixture, err := os.Open("test-fixtures/egg-info/PKG-INFO")
	if err != nil {
		t.Fatalf("failed to open fixture: %+v", err)
	}

	actual, err := parseWheelOrEggMetadata(fixture.Name(), fixture)
	if err != nil {
		t.Fatalf("failed to parse egg-info: %+v", err)
	}

	assertPkgsEqual(t, actual, expected)
}

func TestParseWheelMetadata(t *testing.T) {
	expected := map[string]pkg.Package{
		"Pygments": {
			Name:     "Pygments",
			Version:  "2.6.1",
			Language: pkg.Python,
			Type:     pkg.PythonPkg,
			Licenses: []string{"BSD License"},
		},
	}
	fixture, err := os.Open("test-fixtures/dist-info/METADATA")
	if err != nil {
		t.Fatalf("failed to open fixture: %+v", err)
	}

	actual, err := parseWheelOrEggMetadata(fixture.Name(), fixture)
	if err != nil {
		t.Fatalf("failed to parse dist-info: %+v", err)
	}

	assertPkgsEqual(t, actual, expected)
}
