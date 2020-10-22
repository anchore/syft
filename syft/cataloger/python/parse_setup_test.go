package python

import (
	"os"
	"testing"

	"github.com/anchore/syft/syft/pkg"
)

func TestParseSetup(t *testing.T) {
	expected := map[string]pkg.Package{
		"pathlib3": {
			Name:     "pathlib3",
			Version:  "2.2.0",
			Language: pkg.Python,
			Type:     pkg.PythonPkg,
		},
		"mypy": {
			Name:     "mypy",
			Version:  "v0.770",
			Language: pkg.Python,
			Type:     pkg.PythonPkg,
		},
		"mypy1": {
			Name:     "mypy1",
			Version:  "v0.770",
			Language: pkg.Python,
			Type:     pkg.PythonPkg,
		},
		"mypy2": {
			Name:     "mypy2",
			Version:  "v0.770",
			Language: pkg.Python,
			Type:     pkg.PythonPkg,
		},
		"mypy3": {
			Name:     "mypy3",
			Version:  "v0.770",
			Language: pkg.Python,
			Type:     pkg.PythonPkg,
		},
	}
	fixture, err := os.Open("test-fixtures/setup/setup.py")
	if err != nil {
		t.Fatalf("failed to open fixture: %+v", err)
	}

	actual, err := parseSetup(fixture.Name(), fixture)
	if err != nil {
		t.Fatalf("failed to parse requirements: %+v", err)
	}

	assertPackagesEqual(t, actual, expected)

}
