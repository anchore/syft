package snap

import (
	"testing"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseBaseDpkgYaml(t *testing.T) {
	fixture := "test-fixtures/dpkg.yaml"
	locations := file.NewLocationSet(file.NewLocation(fixture))

	expected := []pkg.Package{
		{
			Name:      "adduser",
			Version:   "3.118ubuntu2",
			Type:      pkg.DebPkg,
			PURL:      "pkg:deb/ubuntu/adduser@3.118ubuntu2",
			Locations: locations,
			Metadata: pkg.SnapEntry{
				SnapType: pkg.SnapTypeBase,
			},
		},
		{
			Name:      "apparmor",
			Version:   "2.13.3-7ubuntu5.3",
			Type:      pkg.DebPkg,
			PURL:      "pkg:deb/ubuntu/apparmor@2.13.3-7ubuntu5.3",
			Locations: locations,
			Metadata: pkg.SnapEntry{
				SnapType: pkg.SnapTypeBase,
			},
		},
		{
			Name:      "gcc-10-base",
			Version:   "10.5.0-1ubuntu1~20.04",
			Type:      pkg.DebPkg,
			PURL:      "pkg:deb/ubuntu/gcc-10-base@10.5.0-1ubuntu1~20.04?arch=amd64",
			Locations: locations,
			Metadata: pkg.SnapEntry{
				SnapType:     pkg.SnapTypeBase,
				Architecture: "amd64", // from package name suffix
			},
		},
	}

	pkgtest.TestFileParser(t, fixture, parseBaseDpkgYaml, expected, nil)
}
