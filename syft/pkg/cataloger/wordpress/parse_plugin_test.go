package wordpress

import (
	"context"
	"io"
	"os"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseWordpressPluginFiles(t *testing.T) {
	fixture := "testdata/glob-paths/wp-content/plugins/akismet/akismet.php"
	locations := file.NewLocationSet(file.NewLocation(fixture))
	ctx := context.TODO()
	var expectedPkg = pkg.Package{
		Name:      "Akismet Anti-spam: Spam Protection",
		Version:   "5.3",
		Locations: locations,
		Type:      pkg.WordpressPluginPkg,
		Licenses: pkg.NewLicenseSet(
			pkg.NewLicenseFromLocationsWithContext(ctx, "GPLv2"),
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

func TestParseWordpressPluginFiles_shortReads(t *testing.T) {
	// a reader that returns one byte per Read must still yield the full header
	fixture := "testdata/glob-paths/wp-content/plugins/akismet/akismet.php"
	f, err := os.Open(fixture)
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })
	reader := file.NewLocationReadCloser(file.NewLocation(fixture), io.NopCloser(iotest.OneByteReader(f)))

	pkgs, _, err := parseWordpressPluginFiles(context.Background(), nil, nil, reader)
	require.NoError(t, err)
	require.Len(t, pkgs, 1)
	assert.Equal(t, "Akismet Anti-spam: Spam Protection", pkgs[0].Name)
	assert.Equal(t, "5.3", pkgs[0].Version)
}
