package python

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
	"github.com/anchore/syft/syft/source"
)

func TestParseRequirementsTxt(t *testing.T) {
	fixture := "test-fixtures/requires/requirements.txt"
	locations := source.NewLocationSet(source.NewLocation(fixture))
	expectedPkgs := []pkg.Package{
		{
			Name:      "flask",
			Version:   "4.0.0",
			PURL:      "pkg:pypi/flask@4.0.0",
			Locations: locations,
			Language:  pkg.Python,
			Type:      pkg.PythonPkg,
		},
		{
			Name:      "foo",
			Version:   "1.0.0",
			PURL:      "pkg:pypi/foo@1.0.0",
			Locations: locations,
			Language:  pkg.Python,
			Type:      pkg.PythonPkg,
		},
		{
			Name:      "SomeProject",
			Version:   "5.4",
			PURL:      "pkg:pypi/SomeProject@5.4",
			Locations: locations,
			Language:  pkg.Python,
			Type:      pkg.PythonPkg,
		},
	}

	var expectedRelationships []artifact.Relationship

	pkgtest.TestFileParser(t, fixture, parseRequirementsTxt, expectedPkgs, expectedRelationships)
}
