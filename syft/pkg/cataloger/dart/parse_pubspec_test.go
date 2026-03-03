package dart

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParsePubspec(t *testing.T) {
	tests := []struct {
		name                  string
		fixture               string
		expectedPackages      []pkg.Package
		expectedRelationships []artifact.Relationship
	}{
		{
			name:    "_macros",
			fixture: "testdata/pubspecs/macros.pubspec.yaml",
			expectedPackages: []pkg.Package{
				{
					Name:      "_macros",
					Version:   "0.3.2",
					PURL:      "pkg:pub/_macros@0.3.2",
					Locations: file.NewLocationSet(file.NewLocation("testdata/pubspecs/macros.pubspec.yaml")),
					Language:  pkg.Dart,
					Type:      pkg.DartPubPkg,
					Metadata: pkg.DartPubspec{
						Repository: "https://github.com/dart-lang/sdk/tree/main/pkg/_macros",
						PublishTo:  "none",
						Environment: &pkg.DartPubspecEnvironment{
							SDK: "^3.4.0-256.0.dev",
						},
					},
				},
			},
			expectedRelationships: nil,
		},
		{
			name:    "_macros",
			fixture: "testdata/pubspecs/appainter.pubspec.yaml",
			expectedPackages: []pkg.Package{
				{
					Name:      "appainter",
					Version:   "2.4.8",
					PURL:      "pkg:pub/appainter@2.4.8",
					Locations: file.NewLocationSet(file.NewLocation("testdata/pubspecs/appainter.pubspec.yaml")),
					Language:  pkg.Dart,
					Type:      pkg.DartPubPkg,
					Metadata: pkg.DartPubspec{
						PublishTo: "none",
						Environment: &pkg.DartPubspecEnvironment{
							SDK:     ">=3.0.0 <4.0.0",
							Flutter: "3.29.3",
						},
					},
				},
			},
			expectedRelationships: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.TestFileParser(t, test.fixture, parsePubspec, test.expectedPackages, test.expectedRelationships)
		})
	}
}
