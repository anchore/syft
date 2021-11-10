package javascript

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
			t.Errorf("%s : unexpected package version: '%s', expected: '%s'", a.Name, a.Version, expectedPkg.Version)
		}

		if a.Language != expectedPkg.Language {
			t.Errorf("%s : bad language: '%+v', expected: '%+v'", a.Name, a.Language, expectedPkg.Language)
		}

		if a.Type != expectedPkg.Type {
			t.Errorf("%s : bad package type: %+v, expected: %+v", a.Name, a.Type, expectedPkg.Type)
		}

		if len(a.Licenses) < len(expectedPkg.Licenses) {
			t.Errorf("%s : bad package licenses count: '%+v'", a.Name, a.Licenses)
		}

	}
}

func TestParsePackageLock(t *testing.T) {
	expected := map[string]pkg.Package{
		"wordwrap": {
			Name:     "wordwrap",
			Version:  "0.0.3",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
		},
		"get-stdin": {
			Name:     "get-stdin",
			Version:  "5.0.1",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
		},
		"minimist": {
			Name:     "minimist",
			Version:  "0.0.10",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
		},
		"optimist": {
			Name:     "optimist",
			Version:  "0.6.1",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
		},
		"string-width": {
			Name:     "string-width",
			Version:  "2.1.1",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
		},
		"strip-ansi": {
			Name:     "strip-ansi",
			Version:  "4.0.0",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
		},
		"strip-eof": {
			Name:     "wordwrap",
			Version:  "1.0.0",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
		},
		"ansi-regex": {
			Name:     "ansi-regex",
			Version:  "3.0.0",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
		},
		"is-fullwidth-code-point": {
			Name:     "is-fullwidth-code-point",
			Version:  "2.0.0",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
		},
		"cowsay": {
			Name:     "cowsay",
			Version:  "1.4.0",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
		},
	}
	fixture, err := os.Open("test-fixtures/pkg-lock/package-lock.json")
	if err != nil {
		t.Fatalf("failed to open fixture: %+v", err)
	}

	// TODO: no relationships are under test yet
	actual, _, err := parsePackageLock(fixture.Name(), fixture)
	if err != nil {
		t.Fatalf("failed to parse package-lock.json: %+v", err)
	}

	assertPkgsEqual(t, actual, expected)

}
