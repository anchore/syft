package apple

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func Test_AppleAppBundleCataloger_Globs(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromDirectory(t, "testdata/install-example").
		ExpectsResolverContentQueries([]string{
			"Applications/Slack.app/Contents/Info.plist",
		}).
		TestCataloger(t, NewAppBundleCataloger())
}

func Test_AppleAppBundleCataloger(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		expected []pkg.Package
	}{
		{
			name:    "xml plist (Slack)",
			fixture: "testdata/install-example",
			expected: []pkg.Package{
				{
					Name:    "Slack",
					Version: "4.50.128",
					Type:    pkg.AppleAppBundlePkg,
					FoundBy: "apple-app-bundle-cataloger",
					Locations: file.NewLocationSet(
						file.NewLocation("Applications/Slack.app/Contents/Info.plist").WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
					),
					PURL: "", // no standard purl type for apple app bundles
					Metadata: pkg.AppleAppBundleEntry{
						BundleIdentifier:     "com.tinyspeck.slackmacgap",
						Name:                 "Slack",
						DisplayName:          "Slack",
						Executable:           "Slack",
						ShortVersion:         "4.50.128",
						Version:              "450000128",
						PackageType:          "APPL",
						MinimumSystemVersion: "12.0",
						Copyright:            "©2026 Slack Technologies LLC, a Salesforce company. All rights reserved.",
						SDKName:              "macosx15.5",
					},
				},
			},
		},
		{
			// platform/array fields; values are from a real Ghostty.app
			name:    "platform fields (Ghostty)",
			fixture: "testdata/native-app-example",
			expected: []pkg.Package{
				{
					Name:    "Ghostty",
					Version: "1.3.1",
					Type:    pkg.AppleAppBundlePkg,
					FoundBy: "apple-app-bundle-cataloger",
					Locations: file.NewLocationSet(
						file.NewLocation("Applications/Ghostty.app/Contents/Info.plist").WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
					),
					PURL: "",
					Metadata: pkg.AppleAppBundleEntry{
						BundleIdentifier:     "com.mitchellh.ghostty",
						Name:                 "Ghostty",
						DisplayName:          "Ghostty",
						Executable:           "ghostty",
						ShortVersion:         "1.3.1",
						Version:              "15212",
						PackageType:          "APPL",
						SupportedPlatforms:   []string{"MacOSX"},
						MinimumSystemVersion: "13.0",
						PlatformName:         "macosx",
						SDKName:              "macosx26.2",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, tt.fixture).
				Expects(tt.expected, nil).
				TestCataloger(t, NewAppBundleCataloger())
		})
	}
}

func Test_parseInfoPlist(t *testing.T) {
	tests := []struct {
		name          string
		fixture       string
		wantName      string
		wantVersion   string
		wantBundleID  string
		wantNoPackage bool
		wantParseErr  bool
	}{
		{
			name:        "name falls back to executable",
			fixture:     "testdata/parse-cases/name-from-executable.plist",
			wantName:    "Exec",
			wantVersion: "1.0",
		},
		{
			name:         "name falls back to bundle identifier",
			fixture:      "testdata/parse-cases/name-from-identifier.plist",
			wantName:     "com.example.app",
			wantVersion:  "1.0",
			wantBundleID: "com.example.app",
		},
		{
			name:        "version falls back to bundle version",
			fixture:     "testdata/parse-cases/version-from-bundle-version.plist",
			wantName:    "Name",
			wantVersion: "42",
		},
		{
			name:          "no package without a name",
			fixture:       "testdata/parse-cases/no-name.plist",
			wantNoPackage: true,
		},
		{
			name:          "no package without a version",
			fixture:       "testdata/parse-cases/no-version.plist",
			wantNoPackage: true,
		},
		{
			name:         "malformed plist returns an error",
			fixture:      "testdata/parse-cases/malformed.plist",
			wantParseErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkgs, _, err := parseFixture(t, tt.fixture)
			if tt.wantParseErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			if tt.wantNoPackage {
				assert.Empty(t, pkgs)
				return
			}

			require.Len(t, pkgs, 1)
			assert.Equal(t, tt.wantName, pkgs[0].Name)
			assert.Equal(t, tt.wantVersion, pkgs[0].Version)
			assert.Equal(t, pkg.AppleAppBundlePkg, pkgs[0].Type)
			assert.Empty(t, pkgs[0].PURL)
			meta, ok := pkgs[0].Metadata.(pkg.AppleAppBundleEntry)
			require.True(t, ok)
			assert.Equal(t, tt.wantBundleID, meta.BundleIdentifier)
		})
	}
}

func parseFixture(t *testing.T, path string) ([]pkg.Package, []artifact.Relationship, error) {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })
	return parseInfoPlist(context.Background(), nil, nil, file.NewLocationReadCloser(file.NewLocation(path), f))
}
