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
			Name:         "./.github/actions/bootstrap",
			Version:      "",
			Type:         pkg.GithubActionPkg,
			Locations:    fixtureLocationSet,
			PURL:         "", // don't have enough context without parsing the git origin, which still may not be accurate
			Dependencies: pkg.UnknownDependencyCompleteness,
		},
		{
			Name:         "actions/cache",
			Version:      "v3",
			Type:         pkg.GithubActionPkg,
			Locations:    fixtureLocationSet,
			PURL:         "pkg:github/actions/cache@v3",
			Dependencies: pkg.UnknownDependencyCompleteness,
		},
		{
			Name:         "actions/cache/restore",
			Version:      "v3",
			Type:         pkg.GithubActionPkg,
			Locations:    fixtureLocationSet,
			PURL:         "pkg:github/actions/cache@v3#restore",
			Dependencies: pkg.UnknownDependencyCompleteness,
		},
		{
			Name:         "actions/cache/save",
			Version:      "v3",
			Type:         pkg.GithubActionPkg,
			Locations:    fixtureLocationSet,
			PURL:         "pkg:github/actions/cache@v3#save",
			Dependencies: pkg.UnknownDependencyCompleteness,
		},
		{
			Name:         "actions/checkout",
			Version:      "v4",
			Type:         pkg.GithubActionPkg,
			Locations:    fixtureLocationSet,
			PURL:         "pkg:github/actions/checkout@v4",
			Dependencies: pkg.UnknownDependencyCompleteness,
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
			Name:         "octo-org/this-repo/.github/workflows/workflow-1.yml",
			Version:      "172239021f7ba04fe7327647b213799853a9eb89",
			Type:         pkg.GithubActionWorkflowPkg,
			Locations:    fixtureLocationSet,
			PURL:         "pkg:github/octo-org/this-repo@172239021f7ba04fe7327647b213799853a9eb89#.github/workflows/workflow-1.yml",
			Dependencies: pkg.CompleteDependencies,
		},
		{
			Name:         "./.github/workflows/workflow-2.yml",
			Version:      "",
			Type:         pkg.GithubActionWorkflowPkg,
			Locations:    fixtureLocationSet,
			PURL:         "", // don't have enough context without parsing the git origin, which still may not be accurate
			Dependencies: pkg.CompleteDependencies,
		},
		{
			Name:         "octo-org/another-repo/.github/workflows/workflow.yml",
			Version:      "v1",
			Type:         pkg.GithubActionWorkflowPkg,
			Locations:    fixtureLocationSet,
			PURL:         "pkg:github/octo-org/another-repo@v1#.github/workflows/workflow.yml",
			Dependencies: pkg.CompleteDependencies,
		},
	}

	var expectedRelationships []artifact.Relationship
	pkgtest.TestFileParser(t, fixture, parseWorkflowForWorkflowUsage, expected, expectedRelationships)
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
