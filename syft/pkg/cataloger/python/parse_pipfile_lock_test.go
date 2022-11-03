package python

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
	"github.com/anchore/syft/syft/source"
)

func TestParsePipFileLock(t *testing.T) {

	fixture := "test-fixtures/pipfile-lock/Pipfile.lock"
	locations := source.NewLocationSet(source.NewLocation(fixture))
	expectedPkgs := []pkg.Package{
		{
			Name:      "aio-pika",
			Version:   "6.8.0",
			PURL:      "pkg:pypi/aio-pika@6.8.0",
			Locations: locations,
			Language:  pkg.Python,
			Type:      pkg.PythonPkg,
		},
		{
			Name:      "aiodns",
			Version:   "2.0.0",
			PURL:      "pkg:pypi/aiodns@2.0.0",
			Locations: locations,
			Language:  pkg.Python,
			Type:      pkg.PythonPkg,
		},
		{
			Name:      "aiohttp",
			Version:   "3.7.4.post0",
			PURL:      "pkg:pypi/aiohttp@3.7.4.post0",
			Locations: locations,
			Language:  pkg.Python,
			Type:      pkg.PythonPkg,
		},
		{
			Name:      "aiohttp-jinja2",
			Version:   "1.4.2",
			PURL:      "pkg:pypi/aiohttp-jinja2@1.4.2",
			Locations: locations,
			Language:  pkg.Python,
			Type:      pkg.PythonPkg,
		},
	}

	// TODO: relationships are not under test
	var expectedRelationships []artifact.Relationship

	pkgtest.TestFileParser(t, fixture, parsePipfileLock, expectedPkgs, expectedRelationships)
}
