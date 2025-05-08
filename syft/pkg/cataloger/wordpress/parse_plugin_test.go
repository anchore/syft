package wordpress

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseWordpressPluginFiles(t *testing.T) {
	fixture := "test-fixtures/glob-paths/wp-content/plugins/akismet/akismet.php"
	locations := file.NewLocationSet(file.NewLocation(fixture))

	var expectedPkg = pkg.Package{
		Name:      "Akismet Anti-spam: Spam Protection",
		Version:   "5.3",
		Locations: locations,
		Type:      pkg.WordpressPluginPkg,
		Licenses: pkg.NewLicenseSet(
			pkg.NewLicenseFromLocations("GPLv2"),
		),
		Language: pkg.PHP,
		Metadata: pkg.WordpressPluginEntry{
			PluginInstallDirectory: "akismet",
			Author:                 "Automattic - Anti-spam Team",
			AuthorURI:              "https://automattic.com/wordpress-plugins/",
		},
	}

	pkgtest.TestFileParser(t, fixture, parseWordpressPluginFiles, []pkg.Package{expectedPkg}, nil)
}

func Test_extractFields(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want map[string]any
	}{
		{
			name: "carriage returns are stripped",
			in:   "Plugin Name: WP Migration\r\nVersion: 5.3\r\nLicense: GPLv3\r\nAuthor: MonsterInsights\r\nAuthor URI: https://servmask.com/\r\n",
			want: map[string]any{
				"name":       "WP Migration",
				"version":    "5.3",
				"license":    "GPLv3",
				"author":     "MonsterInsights",
				"author_uri": "https://servmask.com/",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, extractFields(tt.in))
		})
	}
}
