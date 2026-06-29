package apple

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"howett.net/plist"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func Test_AppleAppBundleCataloger_Globs(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		expected []string
	}{
		{
			name:    "obtain Info.plist files within .app bundles",
			fixture: "test-fixtures/install-example",
			expected: []string{
				"Applications/Slack.app/Contents/Info.plist",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				ExpectsResolverContentQueries(test.expected).
				TestCataloger(t, NewAppBundleCataloger())
		})
	}
}

func Test_AppleAppBundleCataloger(t *testing.T) {
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
					Type:    pkg.AppleAppBundlePkg,
					FoundBy: "apple-app-bundle-cataloger",
					Locations: file.NewLocationSet(
						file.NewLocation("Applications/Slack.app/Contents/Info.plist").WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
					),
					PURL: "", // no standard purl type for apple app bundles
					Metadata: pkg.AppleAppBundleEntry{
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
				TestCataloger(t, NewAppBundleCataloger())
		})
	}
}

// xmlPlist wraps the given dictionary body in a minimal XML plist document.
func xmlPlist(body string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>` + body + `</dict></plist>`
}

func Test_parseInfoPlist_fieldHandling(t *testing.T) {
	tests := []struct {
		name          string
		content       string
		wantName      string
		wantVersion   string
		wantBundleID  string
		wantNoPackage bool
		wantParseErr  bool
	}{
		{
			name:        "display name preferred over name and executable",
			content:     xmlPlist(`<key>CFBundleDisplayName</key><string>Display</string><key>CFBundleName</key><string>Name</string><key>CFBundleExecutable</key><string>Exec</string><key>CFBundleShortVersionString</key><string>1.0</string>`),
			wantName:    "Display",
			wantVersion: "1.0",
		},
		{
			name:        "falls back to bundle name when display name missing",
			content:     xmlPlist(`<key>CFBundleName</key><string>Name</string><key>CFBundleExecutable</key><string>Exec</string><key>CFBundleShortVersionString</key><string>1.0</string>`),
			wantName:    "Name",
			wantVersion: "1.0",
		},
		{
			name:        "falls back to executable when display and bundle name missing",
			content:     xmlPlist(`<key>CFBundleExecutable</key><string>Exec</string><key>CFBundleShortVersionString</key><string>1.0</string>`),
			wantName:    "Exec",
			wantVersion: "1.0",
		},
		{
			name:         "falls back to bundle identifier as last resort name",
			content:      xmlPlist(`<key>CFBundleIdentifier</key><string>com.example.app</string><key>CFBundleShortVersionString</key><string>1.0</string>`),
			wantName:     "com.example.app",
			wantVersion:  "1.0",
			wantBundleID: "com.example.app",
		},
		{
			name:        "falls back to bundle version when short version missing",
			content:     xmlPlist(`<key>CFBundleName</key><string>Name</string><key>CFBundleVersion</key><string>42</string>`),
			wantName:    "Name",
			wantVersion: "42",
		},
		{
			name:          "no package when no name fields present",
			content:       xmlPlist(`<key>CFBundleShortVersionString</key><string>1.0</string>`),
			wantNoPackage: true,
		},
		{
			name:          "no package when no version fields present",
			content:       xmlPlist(`<key>CFBundleName</key><string>Name</string>`),
			wantNoPackage: true,
		},
		{
			name:         "package without bundle identifier still emitted",
			content:      xmlPlist(`<key>CFBundleName</key><string>Name</string><key>CFBundleShortVersionString</key><string>1.0</string>`),
			wantName:     "Name",
			wantVersion:  "1.0",
			wantBundleID: "",
		},
		{
			name:         "malformed plist returns an error",
			content:      "this is not a plist",
			wantParseErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkgs, _, err := parse(t, tt.content)
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

// Test_parseInfoPlist_binary ensures binary-format plists (the common real-world case) parse identically to XML.
func Test_parseInfoPlist_binary(t *testing.T) {
	data, err := plist.Marshal(infoPlist{
		CFBundleName:               "Name",
		CFBundleShortVersionString: "1.0",
		CFBundleIdentifier:         "com.example.app",
	}, plist.BinaryFormat)
	require.NoError(t, err)

	loc := file.NewLocation("Applications/Example.app/Contents/Info.plist")
	pkgs, _, err := parseInfoPlist(context.Background(), nil, nil, file.NewLocationReadCloser(loc, io.NopCloser(strings.NewReader(string(data)))))
	require.NoError(t, err)
	require.Len(t, pkgs, 1)
	assert.Equal(t, "Name", pkgs[0].Name)
	assert.Equal(t, "1.0", pkgs[0].Version)
}

func parse(t *testing.T, content string) ([]pkg.Package, []artifact.Relationship, error) {
	t.Helper()
	loc := file.NewLocation("Applications/Example.app/Contents/Info.plist")
	return parseInfoPlist(context.Background(), nil, nil, file.NewLocationReadCloser(loc, io.NopCloser(strings.NewReader(content))))
}
