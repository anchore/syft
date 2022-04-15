package python

import (
	"github.com/anchore/syft/syft/source"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/anchore/syft/syft/pkg"
)

func TestParsePipFileLock(t *testing.T) {
	expected := []*pkg.Package{
		{
			Name:     "aio-pika",
			Version:  "6.8.0",
			Language: pkg.Python,
			Type:     pkg.PythonPkg,
		},
		{
			Name:     "aiodns",
			Version:  "2.0.0",
			Language: pkg.Python,
			Type:     pkg.PythonPkg,
		},
		{
			Name:     "aiohttp",
			Version:  "3.7.4.post0",
			Language: pkg.Python,
			Type:     pkg.PythonPkg,
		},
		{
			Name:     "aiohttp-jinja2",
			Version:  "1.4.2",
			Language: pkg.Python,
			Type:     pkg.PythonPkg,
		},
	}

	fixture, err := os.Open("test-fixtures/pipfile-lock/Pipfile.lock")
	if err != nil {
		t.Fatalf("failed to open fixture: %+v", err)
	}

	// TODO: no relationships are under test yet
	actual, _, err := parsePipfileLock(fixture.Name(), fixture)
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
