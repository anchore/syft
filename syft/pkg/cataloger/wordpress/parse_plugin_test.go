package wordpress

import (
	"testing"

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
