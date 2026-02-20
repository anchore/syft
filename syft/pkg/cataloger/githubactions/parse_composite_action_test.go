package githubactions

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func Test_parseCompositeActionForActionUsage(t *testing.T) {
	fixture := "test-fixtures/composite-action.yaml"
	fixtureLocationSet := file.NewLocationSet(file.NewLocation(fixture).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))

	expected := []pkg.Package{
		{
			Name:      "actions/checkout",
			Version:   "11",
			Type:      pkg.GithubActionPkg,
			Locations: fixtureLocationSet,
			PURL:      "pkg:github/actions/checkout@11",
			Metadata: pkg.GitHubActionsUseStatement{
				Value:   "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
				Comment: "11",
			},
		},
		{
			Name:      "actions/setup-go",
			Version:   "v5.1.0",
			Type:      pkg.GithubActionPkg,
			Locations: fixtureLocationSet,
			PURL:      "pkg:github/actions/setup-go@v5.1.0",
			Metadata: pkg.GitHubActionsUseStatement{
				Value:   "actions/setup-go@41dfa10bad2bb2ae585af6ee5bb4d7d973ad74ed",
				Comment: "v5.1.0",
			},
		},
		{
			Name:      "actions/setup-go",
			Version:   "v4",
			Type:      pkg.GithubActionPkg,
			Locations: fixtureLocationSet,
			PURL:      "pkg:github/actions/setup-go@v4",
			Metadata:  pkg.GitHubActionsUseStatement{Value: "actions/setup-go@v4"},
		},
		{
			Name:      "actions/cache",
			Version:   "v3",
			Type:      pkg.GithubActionPkg,
			Locations: fixtureLocationSet,
			PURL:      "pkg:github/actions/cache@v3",
			Metadata:  pkg.GitHubActionsUseStatement{Value: "actions/cache@v3"},
		},
	}

	var expectedRelationships []artifact.Relationship
	pkgtest.TestFileParser(t, fixture, parseCompositeActionForActionUsage, expected, expectedRelationships)
}

func Test_corruptCompositeAction(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromFile(t, "test-fixtures/corrupt/composite-action.yaml").
		WithError().
		TestParser(t, parseCompositeActionForActionUsage)
}
