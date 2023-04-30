package python

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseRequirementsTxt(t *testing.T) {
	fixture := "test-fixtures/requires/requirements.txt"
	locations := file.NewLocationSet(file.NewLocation(fixture))
	expectedPkgs := []pkg.Package{
		{
			Name:         "flask",
			Version:      "4.0.0",
			PURL:         "pkg:pypi/flask@4.0.0",
			Locations:    locations,
			Language:     pkg.Python,
			Type:         pkg.PythonPkg,
			MetadataType: pkg.PythonRequirementsMetadataType,
			Metadata: pkg.PythonRequirementsMetadata{
				Name:              "flask",
				Extras:            []string{},
				VersionConstraint: "== 4.0.0",
				URL:               "",
				Markers:           map[string]string{},
			},
		},
		{
			Name:         "foo",
			Version:      "1.0.0",
			PURL:         "pkg:pypi/foo@1.0.0",
			Locations:    locations,
			Language:     pkg.Python,
			Type:         pkg.PythonPkg,
			MetadataType: pkg.PythonRequirementsMetadataType,
			Metadata: pkg.PythonRequirementsMetadata{
				Name:              "foo",
				Extras:            []string{},
				VersionConstraint: "== 1.0.0",
				URL:               "",
				Markers:           map[string]string{},
			},
		},
		{
			Name:         "SomeProject",
			Version:      "5.4",
			PURL:         "pkg:pypi/SomeProject@5.4",
			Locations:    locations,
			Language:     pkg.Python,
			Type:         pkg.PythonPkg,
			MetadataType: pkg.PythonRequirementsMetadataType,
			Metadata: pkg.PythonRequirementsMetadata{
				Name:              "SomeProject",
				Extras:            []string{},
				VersionConstraint: "== 5.4",
				URL:               "",
				Markers:           map[string]string{"python_version": "< '3.8'"},
			},
		},
		{
			Name:         "argh",
			Version:      "0.26.2",
			PURL:         "pkg:pypi/argh@0.26.2",
			Locations:    locations,
			Language:     pkg.Python,
			Type:         pkg.PythonPkg,
			MetadataType: pkg.PythonRequirementsMetadataType,
			Metadata: pkg.PythonRequirementsMetadata{
				Name:              "argh",
				Extras:            []string{},
				VersionConstraint: "== 0.26.2",
				URL:               "",
				Markers:           map[string]string{},
			},
		},
		{
			Name:         "argh",
			Version:      "0.26.3",
			PURL:         "pkg:pypi/argh@0.26.3",
			Locations:    locations,
			Language:     pkg.Python,
			Type:         pkg.PythonPkg,
			MetadataType: pkg.PythonRequirementsMetadataType,
			Metadata: pkg.PythonRequirementsMetadata{
				Name:              "argh",
				Extras:            []string{},
				VersionConstraint: "== 0.26.3",
				URL:               "",
				Markers:           map[string]string{},
			},
		},
		{
			Name:         "celery",
			Version:      "4.4.7",
			PURL:         "pkg:pypi/celery@4.4.7",
			Locations:    locations,
			Language:     pkg.Python,
			Type:         pkg.PythonPkg,
			MetadataType: pkg.PythonRequirementsMetadataType,
			Metadata: pkg.PythonRequirementsMetadata{
				Name:              "celery",
				Extras:            []string{"redis", "pytest"},
				VersionConstraint: "== 4.4.7",
				URL:               "",
				Markers:           map[string]string{},
			},
		},
		{
			Name:         "requests",
			Version:      "2.8",
			PURL:         "pkg:pypi/requests@2.8",
			Locations:    locations,
			Language:     pkg.Python,
			Type:         pkg.PythonPkg,
			MetadataType: pkg.PythonRequirementsMetadataType,
			Metadata: pkg.PythonRequirementsMetadata{
				Name:              "requests",
				Extras:            []string{"security"},
				VersionConstraint: "== 2.8",
				URL:               "",
				Markers: map[string]string{
					"python_version": `< "2.7"`,
					"sys_platform":   `== "linux"`,
				},
			},
		},
		{
			Name:         "GithubSampleProject",
			Version:      "3.7.1",
			PURL:         "pkg:pypi/GithubSampleProject@3.7.1",
			Locations:    locations,
			Language:     pkg.Python,
			Type:         pkg.PythonPkg,
			MetadataType: pkg.PythonRequirementsMetadataType,
			Metadata: pkg.PythonRequirementsMetadata{
				Name:              "GithubSampleProject",
				Extras:            []string{},
				VersionConstraint: "== 3.7.1",
				URL:               "git+https://github.com/owner/repo@releases/tag/v3.7.1",
				Markers:           map[string]string{},
			},
		},
	}

	var expectedRelationships []artifact.Relationship

	pkgtest.TestFileParser(t, fixture, parseRequirementsTxt, expectedPkgs, expectedRelationships)
}
