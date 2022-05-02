package python

import (
	"github.com/anchore/syft/syft/source"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/anchore/syft/syft/pkg"
)

func TestParseSetup(t *testing.T) {
	expected := []*pkg.Package{
		{
			Name:     "pathlib3",
			Version:  "2.2.0",
			Language: pkg.Python,
			Type:     pkg.PythonPkg,
		},
		{
			Name:     "mypy",
			Version:  "v0.770",
			Language: pkg.Python,
			Type:     pkg.PythonPkg,
		},
		{
			Name:     "mypy1",
			Version:  "v0.770",
			Language: pkg.Python,
			Type:     pkg.PythonPkg,
		},
		{
			Name:     "mypy2",
			Version:  "v0.770",
			Language: pkg.Python,
			Type:     pkg.PythonPkg,
		},
		{
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

	// TODO: no relationships are under test yet
	actual, _, err := parseSetup(fixture.Name(), fixture)
	if err != nil {
		t.Fatalf("failed to parse requirements: %+v", err)
	}

	if diff := cmp.Diff(expected, actual,
		cmp.AllowUnexported(pkg.Package{}),
		cmp.Comparer(
			func(x, y source.LocationSet) bool {
				return cmp.Equal(x.ToSlice(), y.ToSlice())
			},
		),
	); diff != "" {
		t.Errorf("unexpected result from parsing (-expected +actual)\n%s", diff)
	}
}
