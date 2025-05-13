package python

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParsePoetryLock(t *testing.T) {
	fixture := "test-fixtures/poetry/dev-deps/poetry.lock"
	locations := file.NewLocationSet(file.NewLocation(fixture))
	expectedPkgs := []pkg.Package{
		{
			Name:      "added-value",
			Version:   "0.14.2",
			PURL:      "pkg:pypi/added-value@0.14.2",
			Locations: locations,
			Language:  pkg.Python,
			Type:      pkg.PythonPkg,
			Metadata: pkg.PythonPoetryLockEntry{
				Index: "https://test.pypi.org/simple",
				Dependencies: []pkg.PythonPoetryLockDependencyEntry{
					{Name: "docutils", Version: "*"},
					{Name: "msal", Version: ">=0.4.1,<2.0.0"},
					{Name: "natsort", Version: "*"},
					{Name: "packaging", Version: "*"},
					{Name: "portalocker", Version: ">=1.0,<3", Markers: `platform_system != "Windows"`},
					{Name: "portalocker", Version: ">=1.6,<3", Markers: `platform_system == "Windows"`},
					{Name: "six", Version: "*"},
					{Name: "sphinx", Version: "*"},
				},
				Extras: []pkg.PythonPoetryLockExtraEntry{
					{
						Name:         "deploy",
						Dependencies: []string{"bumpversion", "twine", "wheel"},
					},
					{
						Name:         "docs",
						Dependencies: []string{"sphinx", "sphinx-rtd-theme"},
					},
					{
						Name:         "test",
						Dependencies: []string{"pytest", "pytest-cov", "coveralls", "beautifulsoup4", "hypothesis"},
					},
				},
			},
		},
		{
			Name:      "alabaster",
			Version:   "0.7.12",
			PURL:      "pkg:pypi/alabaster@0.7.12",
			Locations: locations,
			Language:  pkg.Python,
			Type:      pkg.PythonPkg,
			Metadata:  pkg.PythonPoetryLockEntry{Index: "https://pypi.org/simple"},
		},
		{
			Name:      "appnope",
			Version:   "0.1.0",
			PURL:      "pkg:pypi/appnope@0.1.0",
			Locations: locations,
			Language:  pkg.Python,
			Type:      pkg.PythonPkg,
			Metadata:  pkg.PythonPoetryLockEntry{Index: "https://pypi.org/simple"},
		},
		{
			Name:      "asciitree",
			Version:   "0.3.3",
			PURL:      "pkg:pypi/asciitree@0.3.3",
			Locations: locations,
			Language:  pkg.Python,
			Type:      pkg.PythonPkg,
			Metadata:  pkg.PythonPoetryLockEntry{Index: "https://pypi.org/simple"},
		},
	}

	var expectedRelationships []artifact.Relationship

	pkgtest.TestFileParser(t, fixture, parsePoetryLock, expectedPkgs, expectedRelationships)
}

func Test_corruptPoetryLock(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromFile(t, "test-fixtures/glob-paths/src/poetry.lock").
		WithError().
		TestParser(t, parsePoetryLock)
}
