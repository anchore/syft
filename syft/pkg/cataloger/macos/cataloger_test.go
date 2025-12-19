package macos

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func Test_MacOSAppCataloger_Globs(t *testing.T) {
	fixture := "test-fixtures/install-example"

	expected := []string{
		"Applications/Slack.app/Contents/Info.plist",
	}

	pkgtest.NewCatalogTester().
		FromDirectory(t, fixture).
		ExpectsResolverContentQueries(expected).
		TestCataloger(t, NewAppCataloger())
}

func Test_MacOSAppCataloger(t *testing.T) {
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
					Name:    "Slack",
					Version: "4.44.65",
					Type:    pkg.MacOSAppPkg,
					FoundBy: "macos-app-cataloger",
					Locations: file.NewLocationSet(
						file.NewLocation("Applications/Slack.app/Contents/Info.plist").WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
					),
					PURL: "pkg:macos-app/Slack@4.44.65",
					Metadata: pkg.MacOSAppEntry{
						BundleIdentifier: "com.tinyspeck.slackmacgap",
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
				TestCataloger(t, NewAppCataloger())
		})
	}
}
