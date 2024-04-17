package gitlab

import (
	"testing"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseVersionManifestFile(t *testing.T) {
	fixture := "test-fixtures/glob-paths/opt/gitlab/version-manifest.json"
	locations := file.NewLocationSet(file.NewLocation(fixture))

	var expectedPkg = pkg.Package{
		Name:      "openssl",
		Version:   "1.1.1q",
		Locations: locations,
		Licenses: pkg.NewLicenseSet(
			pkg.NewLicenseFromLocations("OpenSSL"),
		),
		PURL: "pkg:gitlab/omnibus-mirror/openssl",
	}

	pkgtest.TestFileParser(t, fixture, parseVersionManifest, []pkg.Package{expectedPkg}, nil)
}
