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
			Licenses: []string{},
		},
		"mypy": {
			Name:     "mypy",
			Version:  "v0.770",
			Language: pkg.Python,
			Type:     pkg.PythonPkg,
			Licenses: []string{},
		},
		"mypy1": {
			Name:     "mypy1",
			Version:  "v0.770",
			Language: pkg.Python,
			Type:     pkg.PythonPkg,
			Licenses: []string{},
		},
		"mypy2": {
			Name:     "mypy2",
			Version:  "v0.770",
			Language: pkg.Python,
			Type:     pkg.PythonPkg,
			Licenses: []string{},
		},
		"mypy3": {
			Name:     "mypy3",
			Version:  "v0.770",
			Language: pkg.Python,
			Type:     pkg.PythonPkg,
			Licenses: []string{},
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

	assertPkgsEqual(t, actual, expected)

}
