package homebrew

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func Test_HomebrewCataloger_Globs(t *testing.T) {
	fixture := "test-fixtures/install-example"

	expected := []string{
		"opt/homebrew/Cellar/foo/1.2.3/.brew/foo.rb",
		"opt/homebrew/Library/Taps/testorg/sometap/Formula/bar.rb",
	}

	pkgtest.NewCatalogTester().
		FromDirectory(t, fixture).
		ExpectsResolverContentQueries(expected).
		TestCataloger(t, NewCataloger())
}

func Test_HomebrewCataloger(t *testing.T) {

	tests := []struct {
		name         string
		path         string
		expected     []pkg.Package
		expectedRels []artifact.Relationship
	}{
		{
			name: "go case",
			path: "test-fixtures/install-example",
			expected: []pkg.Package{
				{
					Name:    "bar",
					Version: "4.5.6",
					Type:    pkg.HomebrewPkg,
					Locations: file.NewLocationSet(
						file.NewLocation("opt/homebrew/Library/Taps/testorg/sometap/Formula/bar.rb").WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
					),
					Licenses: pkg.NewLicenseSet(pkg.NewLicensesFromValues("MIT")...),
					FoundBy:  "homebrew-cataloger",
					PURL:     "pkg:brew/bar@4.5.6",
					Metadata: pkg.HomebrewFormula{
						Tap:         "testorg/sometap",
						Homepage:    "https://example.com/bar",
						Description: "A test Homebrew formula for bar",
					},
				},
				{
					Name:    "foo",
					Version: "1.2.3",
					Type:    pkg.HomebrewPkg,
					Locations: file.NewLocationSet(
						file.NewLocation("opt/homebrew/Cellar/foo/1.2.3/.brew/foo.rb").WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
					),
					Licenses: pkg.NewLicenseSet(pkg.NewLicensesFromValues("Apache 2.0")...),
					FoundBy:  "homebrew-cataloger",
					PURL:     "pkg:brew/foo@1.2.3",
					Metadata: pkg.HomebrewFormula{
						Homepage:    "https://example.com/foo",
						Description: "A test Homebrew formula for Foo",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, tt.path).
				Expects(tt.expected, tt.expectedRels).
				TestCataloger(t, NewCataloger())
		})
	}

}
