package githubactions

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func Test_parseWorkflowForActionUsage(t *testing.T) {
	fixture := "test-fixtures/workflow-multi-job.yaml"
	fixtureLocationSet := file.NewLocationSet(file.NewLocation(fixture).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))

	expected := []pkg.Package{
		{
			Name:      "./.github/actions/bootstrap",
			Version:   "",
			Type:      pkg.GithubActionPkg,
			Locations: fixtureLocationSet,
			PURL:      "", // don't have enough context without parsing the git origin, which still may not be accurate
			Metadata:  pkg.GitHubActionsUseStatement{Value: "./.github/actions/bootstrap"},
		},
		{
			Name:      "actions/cache",
			Version:   "v3",
			Type:      pkg.GithubActionPkg,
			Locations: fixtureLocationSet,
			PURL:      "pkg:github/actions/cache@v3",
			Metadata:  pkg.GitHubActionsUseStatement{Value: "actions/cache@v3"},
		},
		{
			Name:      "actions/cache/restore",
			Version:   "v3",
			Type:      pkg.GithubActionPkg,
			Locations: fixtureLocationSet,
			PURL:      "pkg:github/actions/cache@v3#restore",
			Metadata:  pkg.GitHubActionsUseStatement{Value: "actions/cache/restore@v3"},
		},
		{
			Name:      "actions/cache/save",
			Version:   "v3",
			Type:      pkg.GithubActionPkg,
			Locations: fixtureLocationSet,
			PURL:      "pkg:github/actions/cache@v3#save",
			Metadata:  pkg.GitHubActionsUseStatement{Value: "actions/cache/save@v3"},
		},
		{
			Name:      "actions/checkout",
			Version:   "v4",
			Type:      pkg.GithubActionPkg,
			Locations: fixtureLocationSet,
			PURL:      "pkg:github/actions/checkout@v4",
			Metadata:  pkg.GitHubActionsUseStatement{Value: "actions/checkout@v4"},
		},
	}

	var expectedRelationships []artifact.Relationship
	pkgtest.TestFileParser(t, fixture, parseWorkflowForActionUsage, expected, expectedRelationships)
}

func Test_parseWorkflowForWorkflowUsage(t *testing.T) {
	fixture := "test-fixtures/call-shared-workflow.yaml"
	fixtureLocationSet := file.NewLocationSet(file.NewLocation(fixture).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))

	expected := []pkg.Package{
		{
			Name:      "octo-org/this-repo/.github/workflows/workflow-1.yml",
			Version:   "172239021f7ba04fe7327647b213799853a9eb89",
			Type:      pkg.GithubActionWorkflowPkg,
			Locations: fixtureLocationSet,
			PURL:      "pkg:github/octo-org/this-repo@172239021f7ba04fe7327647b213799853a9eb89#.github/workflows/workflow-1.yml",
			Metadata: pkg.GitHubActionsUseStatement{
				Value: "octo-org/this-repo/.github/workflows/workflow-1.yml@172239021f7ba04fe7327647b213799853a9eb89",
			},
		},
		{
			Name:      "./.github/workflows/workflow-2.yml",
			Version:   "",
			Type:      pkg.GithubActionWorkflowPkg,
			Locations: fixtureLocationSet,
			PURL:      "", // don't have enough context without parsing the git origin, which still may not be accurate
			Metadata:  pkg.GitHubActionsUseStatement{Value: "./.github/workflows/workflow-2.yml"},
		},
		{
			Name:      "octo-org/another-repo/.github/workflows/workflow.yml",
			Version:   "v1",
			Type:      pkg.GithubActionWorkflowPkg,
			Locations: fixtureLocationSet,
			PURL:      "pkg:github/octo-org/another-repo@v1#.github/workflows/workflow.yml",
			Metadata:  pkg.GitHubActionsUseStatement{Value: "octo-org/another-repo/.github/workflows/workflow.yml@v1"},
		},
	}

	var expectedRelationships []artifact.Relationship
	pkgtest.TestFileParser(t, fixture, parseWorkflowForWorkflowUsage, expected, expectedRelationships)
}

func Test_parseWorkflowForVersionComments(t *testing.T) {
	fixture := "test-fixtures/workflow-with-version-comments.yaml"
	fixtureLocationSet := file.NewLocationSet(file.NewLocation(fixture).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))

	expected := []pkg.Package{
		{
			Name:      "./.github/actions/bootstrap",
			Version:   "",
			Type:      pkg.GithubActionPkg,
			Locations: fixtureLocationSet,
			PURL:      "", // don't have enough context without parsing the git origin, which still may not be accurate
			Metadata: pkg.GitHubActionsUseStatement{
				Value: "./.github/actions/bootstrap",
			},
		},
		{
			Name:      "actions/checkout",
			Version:   "v4.2.2",
			Type:      pkg.GithubActionPkg,
			Locations: fixtureLocationSet,
			PURL:      "pkg:github/actions/checkout@v4.2.2",
			Metadata: pkg.GitHubActionsUseStatement{
				Value:   "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
				Comment: "v4.2.2",
			},
		},
	}

	var expectedRelationships []artifact.Relationship
	pkgtest.TestFileParser(t, fixture, parseWorkflowForActionUsage, expected, expectedRelationships)
}

func Test_corruptActionWorkflow(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromFile(t, "test-fixtures/corrupt/workflow-multi-job.yaml").
		WithError().
		TestParser(t, parseWorkflowForActionUsage)
}

func Test_corruptWorkflowWorkflow(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromFile(t, "test-fixtures/corrupt/workflow-multi-job.yaml").
		WithError().
		TestParser(t, parseWorkflowForWorkflowUsage)
}
