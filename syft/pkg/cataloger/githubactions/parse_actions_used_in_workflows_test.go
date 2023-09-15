package githubactions

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func Test_parseActionsUsedInWorkflows(t *testing.T) {
	fixture := "test-fixtures/workflow-multi-job.yaml"
	fixtureLocationSet := file.NewLocationSet(file.NewLocation(fixture).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))

	expected := []pkg.Package{
		{
			Name:      "./.github/actions/bootstrap",
			Version:   "",
			Type:      pkg.GithubActionPkg,
			Locations: fixtureLocationSet,
			PURL:      "", // don't have enough context without parsing the git origin, which still may not be accurate
		},
		{
			Name:      "actions/cache",
			Version:   "v3",
			Type:      pkg.GithubActionPkg,
			Locations: fixtureLocationSet,
			PURL:      "pkg:github/actions/cache@v3",
		},
		{
			Name:      "actions/cache/restore",
			Version:   "v3",
			Type:      pkg.GithubActionPkg,
			Locations: fixtureLocationSet,
			PURL:      "pkg:github/actions/cache@v3#restore",
		},
		{
			Name:      "actions/cache/save",
			Version:   "v3",
			Type:      pkg.GithubActionPkg,
			Locations: fixtureLocationSet,
			PURL:      "pkg:github/actions/cache@v3#save",
		},
		{
			Name:      "actions/checkout",
			Version:   "v4",
			Type:      pkg.GithubActionPkg,
			Locations: fixtureLocationSet,
			PURL:      "pkg:github/actions/checkout@v4",
		},
	}

	var expectedRelationships []artifact.Relationship
	pkgtest.TestFileParser(t, fixture, parseActionsUsedInWorkflows, expected, expectedRelationships)
}
