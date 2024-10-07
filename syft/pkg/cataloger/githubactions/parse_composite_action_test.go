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
			Name:      "actions/setup-go",
			Version:   "v4",
			Type:      pkg.GithubActionPkg,
			Locations: fixtureLocationSet,
			PURL:      "pkg:github/actions/setup-go@v4",
		},
		{
			Name:      "actions/cache",
			Version:   "v3",
			Type:      pkg.GithubActionPkg,
			Locations: fixtureLocationSet,
			PURL:      "pkg:github/actions/cache@v3",
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
