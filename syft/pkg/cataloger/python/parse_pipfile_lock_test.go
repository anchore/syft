package python

import (
	"os"
	"testing"

	"github.com/anchore/syft/syft/pkg"
)

func TestParsePipFileLock(t *testing.T) {
	expected := map[string]pkg.Package{
		"aio-pika": {
			Name:     "aio-pika",
			Version:  "6.8.0",
			Language: pkg.Python,
			Type:     pkg.PythonPkg,
		},
		"aiodns": {
			Name:     "aiodns",
			Version:  "2.0.0",
			Language: pkg.Python,
			Type:     pkg.PythonPkg,
		},
		"aiohttp": {
			Name:     "aiohttp",
			Version:  "3.7.4.post0",
			Language: pkg.Python,
			Type:     pkg.PythonPkg,
		},
		"aiohttp-jinja2": {
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

	actual, err := parsePipfileLock(fixture.Name(), fixture)
	if err != nil {
		t.Fatalf("failed to parse requirements: %+v", err)
	}

	assertPackagesEqual(t, actual, expected)

}
