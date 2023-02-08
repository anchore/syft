package deb

import (
	"testing"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
	"github.com/anchore/syft/syft/source"
)

func TestDpkgCataloger(t *testing.T) {
	expected := []pkg.Package{
		{
			Name:     "libpam-runtime",
			Version:  "1.1.8-3.6",
			FoundBy:  "dpkgdb-cataloger",
			Licenses: internal.LogicalStrings{Simple: []string{"GPL-1", "GPL-2", "LGPL-2.1"}},
			Locations: source.NewLocationSet(
				source.NewVirtualLocation("/var/lib/dpkg/status", "/var/lib/dpkg/status"),
				source.NewVirtualLocation("/var/lib/dpkg/info/libpam-runtime.md5sums", "/var/lib/dpkg/info/libpam-runtime.md5sums"),
				source.NewVirtualLocation("/var/lib/dpkg/info/libpam-runtime.conffiles", "/var/lib/dpkg/info/libpam-runtime.conffiles"),
				source.NewVirtualLocation("/usr/share/doc/libpam-runtime/copyright", "/usr/share/doc/libpam-runtime/copyright"),
			),
			Type:         pkg.DebPkg,
			MetadataType: pkg.DpkgMetadataType,
			Metadata: pkg.DpkgMetadata{
				Package:       "libpam-runtime",
				Source:        "pam",
				Version:       "1.1.8-3.6",
				Architecture:  "all",
				Maintainer:    "Steve Langasek <vorlon@debian.org>",
				InstalledSize: 1016,
				Description: `Runtime support for the PAM library
 Contains configuration files and  directories required for
 authentication  to work on Debian systems.  This package is required
 on almost all installations.`,
				Files: []pkg.DpkgFileRecord{
					{
						Path: "/etc/pam.conf",
						Digest: &file.Digest{
							Algorithm: "md5",
							Value:     "87fc76f18e98ee7d3848f6b81b3391e5",
						},
						IsConfigFile: true,
					},
					{
						Path: "/etc/pam.d/other",
						Digest: &file.Digest{
							Algorithm: "md5",
							Value:     "31aa7f2181889ffb00b87df4126d1701",
						},
						IsConfigFile: true,
					},
					{Path: "/lib/x86_64-linux-gnu/libz.so.1.2.11", Digest: &file.Digest{
						Algorithm: "md5",
						Value:     "55f905631797551d4d936a34c7e73474",
					}},
					{Path: "/usr/share/doc/zlib1g/changelog.Debian.gz", Digest: &file.Digest{
						Algorithm: "md5",
						Value:     "cede84bda30d2380217f97753c8ccf3a",
					}},
					{Path: "/usr/share/doc/zlib1g/changelog.gz", Digest: &file.Digest{
						Algorithm: "md5",
						Value:     "f3c9dafa6da7992c47328b4464f6d122",
					}},
					{Path: "/usr/share/doc/zlib1g/copyright", Digest: &file.Digest{
						Algorithm: "md5",
						Value:     "a4fae96070439a5209a62ae5b8017ab2",
					}},
				},
			},
		},
	}

	c := NewDpkgdbCataloger()

	pkgtest.NewCatalogTester().
		WithImageResolver(t, "image-dpkg").
		IgnoreLocationLayer(). // this fixture can be rebuilt, thus the layer ID will change
		Expects(expected, nil).
		TestCataloger(t, c)
}

func TestCataloger_Globs(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		expected []string
	}{
		{
			name:    "obtain db status files",
			fixture: "test-fixtures/glob-paths",
			expected: []string{
				"var/lib/dpkg/status",
				"var/lib/dpkg/status.d/pkg-1.0",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				ExpectsResolverContentQueries(test.expected).
				TestCataloger(t, NewDpkgdbCataloger())
		})
	}
}
