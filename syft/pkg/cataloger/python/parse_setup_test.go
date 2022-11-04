package python

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
	"github.com/anchore/syft/syft/source"
)

func TestParseSetup(t *testing.T) {
	fixture := "test-fixtures/setup/setup.py"
	locations := source.NewLocationSet(source.NewLocation(fixture))
	expectedPkgs := []pkg.Package{
		{
			Name:      "pathlib3",
			Version:   "2.2.0",
			PURL:      "pkg:pypi/pathlib3@2.2.0",
			Locations: locations,
			Language:  pkg.Python,
			Type:      pkg.PythonPkg,
		},
		{
			Name:      "mypy",
			Version:   "v0.770",
			PURL:      "pkg:pypi/mypy@v0.770",
			Locations: locations,
			Language:  pkg.Python,
			Type:      pkg.PythonPkg,
		},
		{
			Name:      "mypy1",
			Version:   "v0.770",
			PURL:      "pkg:pypi/mypy1@v0.770",
			Locations: locations,
			Language:  pkg.Python,
			Type:      pkg.PythonPkg,
		},
		{
			Name:      "mypy2",
			Version:   "v0.770",
			PURL:      "pkg:pypi/mypy2@v0.770",
			Locations: locations,
			Language:  pkg.Python,
			Type:      pkg.PythonPkg,
		},
		{
			Name:      "mypy3",
			Version:   "v0.770",
			PURL:      "pkg:pypi/mypy3@v0.770",
			Locations: locations,
			Language:  pkg.Python,
			Type:      pkg.PythonPkg,
		},
	}

	var expectedRelationships []artifact.Relationship

	pkgtest.TestFileParser(t, fixture, parseSetup, expectedPkgs, expectedRelationships)
}
