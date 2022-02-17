package python

import (
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/anchore/syft/syft/pkg"
)

func TestParseRequirementsTxt(t *testing.T) {
	expected := []*pkg.Package{
		{
			Name:     "flask",
			Version:  "4.0.0",
			Language: pkg.Python,
			Type:     pkg.PythonPkg,
		},
		{
			Name:     "foo",
			Version:  "1.0.0",
			Language: pkg.Python,
			Type:     pkg.PythonPkg,
		},
		{
			Name:     "SomeProject",
			Version:  "5.4",
			Language: pkg.Python,
			Type:     pkg.PythonPkg,
		},
	}

	fixture, err := os.Open("test-fixtures/requires/requirements.txt")
	if err != nil {
		t.Fatalf("failed to open fixture: %+v", err)
	}

	// TODO: no relationships are under test yet
	actual, _, err := parseRequirementsTxt(fixture.Name(), fixture)
	if err != nil {
		t.Fatalf("failed to parse requirements: %+v", err)
	}

	if diff := cmp.Diff(expected, actual, cmp.AllowUnexported(pkg.Package{})); diff != "" {
		t.Errorf("unexpected result from parsing (-expected +actual)\n%s", diff)
	}
}
