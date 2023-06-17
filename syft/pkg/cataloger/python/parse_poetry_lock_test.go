package python

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParsePoetryLock(t *testing.T) {
	fixture := "test-fixtures/poetry/poetry.lock"
	locations := file.NewLocationSet(file.NewLocation(fixture))
	expectedPkgs := []pkg.Package{
		{
			Name:      "added-value",
			Version:   "0.14.2",
			PURL:      "pkg:pypi/added-value@0.14.2",
			Locations: locations,
			Language:  pkg.Python,
			Type:      pkg.PythonPkg,
		},
		{
			Name:      "alabaster",
			Version:   "0.7.12",
			PURL:      "pkg:pypi/alabaster@0.7.12",
			Locations: locations,
			Language:  pkg.Python,
			Type:      pkg.PythonPkg,
		},
		{
			Name:      "appnope",
			Version:   "0.1.0",
			PURL:      "pkg:pypi/appnope@0.1.0",
			Locations: locations,
			Language:  pkg.Python,
			Type:      pkg.PythonPkg,
		},
		{
			Name:      "asciitree",
			Version:   "0.3.3",
			PURL:      "pkg:pypi/asciitree@0.3.3",
			Locations: locations,
			Language:  pkg.Python,
			Type:      pkg.PythonPkg,
		},
	}

	// TODO: relationships are not under test
	var expectedRelationships []artifact.Relationship

	pkgtest.TestFileParser(t, fixture, parsePoetryLock, expectedPkgs, expectedRelationships)
}
