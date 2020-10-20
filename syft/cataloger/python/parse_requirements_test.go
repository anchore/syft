package python

import (
	"os"
	"testing"

	"github.com/anchore/syft/syft/pkg"
)

func TestParseRequirementsTxt(t *testing.T) {
	expected := map[string]pkg.Package{
		"foo": {
			Name:     "foo",
			Version:  "1.0.0",
			Language: pkg.Python,
			Type:     pkg.PythonPkg,
			Licenses: []string{},
		},
		"flask": {
			Name:     "flask",
			Version:  "4.0.0",
			Language: pkg.Python,
			Type:     pkg.PythonPkg,
			Licenses: []string{},
		},
	}
	fixture, err := os.Open("test-fixtures/requires/requirements.txt")
	if err != nil {
		t.Fatalf("failed to open fixture: %+v", err)
	}

	actual, err := parseRequirementsTxt(fixture.Name(), fixture)
	if err != nil {
		t.Fatalf("failed to parse requirements: %+v", err)
	}

	assertPkgsEqual(t, actual, expected)

}
