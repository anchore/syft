package deb

import (
	"testing"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestDpkgCataloger(t *testing.T) {
	tests := []struct {
		name     string
		expected []pkg.Package
	}{
		{
			name: "image-dpkg",
			expected: []pkg.Package{
				{
					Name:    "libpam-runtime",
					Version: "1.1.8-3.6",
					FoundBy: "dpkgdb-cataloger",
					Licenses: pkg.NewLicenseSet(
						pkg.NewLicenseFromLocations("GPL-1", file.NewVirtualLocation("/usr/share/doc/libpam-runtime/copyright", "/usr/share/doc/libpam-runtime/copyright")),
						pkg.NewLicenseFromLocations("GPL-2", file.NewVirtualLocation("/usr/share/doc/libpam-runtime/copyright", "/usr/share/doc/libpam-runtime/copyright")),
						pkg.NewLicenseFromLocations("LGPL-2.1", file.NewVirtualLocation("/usr/share/doc/libpam-runtime/copyright", "/usr/share/doc/libpam-runtime/copyright")),
					),
					Locations: file.NewLocationSet(
						file.NewVirtualLocation("/var/lib/dpkg/status", "/var/lib/dpkg/status"),
						file.NewVirtualLocation("/var/lib/dpkg/info/libpam-runtime.md5sums", "/var/lib/dpkg/info/libpam-runtime.md5sums"),
						file.NewVirtualLocation("/var/lib/dpkg/info/libpam-runtime.conffiles", "/var/lib/dpkg/info/libpam-runtime.conffiles"),
						file.NewVirtualLocation("/usr/share/doc/libpam-runtime/copyright", "/usr/share/doc/libpam-runtime/copyright"),
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
			},
		},
		{
			name: "image-distroless-deb",
			expected: []pkg.Package{
				{
					Name:    "libsqlite3-0",
					Version: "3.34.1-3",
					FoundBy: "dpkgdb-cataloger",
					Licenses: pkg.NewLicenseSet(
						pkg.NewLicenseFromLocations("public-domain", file.NewVirtualLocation("/usr/share/doc/libsqlite3-0/copyright", "/usr/share/doc/libsqlite3-0/copyright")),
						pkg.NewLicenseFromLocations("GPL-2+", file.NewVirtualLocation("/usr/share/doc/libsqlite3-0/copyright", "/usr/share/doc/libsqlite3-0/copyright")),
						pkg.NewLicenseFromLocations("GPL-2", file.NewVirtualLocation("/usr/share/doc/libsqlite3-0/copyright", "/usr/share/doc/libsqlite3-0/copyright")),
					),
					Locations: file.NewLocationSet(
						file.NewVirtualLocation("/var/lib/dpkg/status.d/libsqlite3-0", "/var/lib/dpkg/status.d/libsqlite3-0"),
						file.NewVirtualLocation("/var/lib/dpkg/status.d/libsqlite3-0.md5sums", "/var/lib/dpkg/status.d/libsqlite3-0.md5sums"),
						file.NewVirtualLocation("/usr/share/doc/libsqlite3-0/copyright", "/usr/share/doc/libsqlite3-0/copyright"),
					),
					Type:         pkg.DebPkg,
					MetadataType: pkg.DpkgMetadataType,
					Metadata: pkg.DpkgMetadata{
						Package:       "libsqlite3-0",
						Source:        "sqlite3",
						Version:       "3.34.1-3",
						Architecture:  "arm64",
						Maintainer:    "Laszlo Boszormenyi (GCS) <gcs@debian.org>",
						InstalledSize: 1490,
						Description: `SQLite 3 shared library
 SQLite is a C library that implements an SQL database engine.
 Programs that link with the SQLite library can have SQL database
 access without running a separate RDBMS process.`,
						Files: []pkg.DpkgFileRecord{
							{Path: "/usr/lib/aarch64-linux-gnu/libsqlite3.so.0.8.6", Digest: &file.Digest{
								Algorithm: "md5",
								Value:     "e11d70c96979a1328ae4e7e50542782b",
							}},
							{Path: "/usr/share/doc/libsqlite3-0/README.Debian", Digest: &file.Digest{
								Algorithm: "md5",
								Value:     "9d8facc2fa9d2df52f1c7cb4e5fa4741",
							}},
							{Path: "/usr/share/doc/libsqlite3-0/changelog.Debian.gz", Digest: &file.Digest{
								Algorithm: "md5",
								Value:     "a58942e742f5056be0595e6ba69a323f",
							}},
							{Path: "/usr/share/doc/libsqlite3-0/changelog.gz", Digest: &file.Digest{
								Algorithm: "md5",
								Value:     "52317be84c3ca44b7888c6921131e37d",
							}},
							{Path: "/usr/share/doc/libsqlite3-0/changelog.html.gz", Digest: &file.Digest{
								Algorithm: "md5",
								Value:     "a856310354e6c8768e85b39ae838dd0a",
							}},
							{Path: "/usr/share/doc/libsqlite3-0/copyright", Digest: &file.Digest{
								Algorithm: "md5",
								Value:     "be64db3e095486e5e105652c51199358",
							}},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewDpkgdbCataloger()
			pkgtest.NewCatalogTester().
				WithImageResolver(t, tt.name).
				IgnoreLocationLayer(). // this fixture can be rebuilt, thus the layer ID will change
				Expects(tt.expected, nil).
				TestCataloger(t, c)
		})
	}
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
				"usr/lib/opkg/status",
				"usr/lib/opkg/info/pkg-1.0.control",
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
