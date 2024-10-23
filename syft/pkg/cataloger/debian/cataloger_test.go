package debian

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

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
					FoundBy: "dpkg-db-cataloger",
					Licenses: pkg.NewLicenseSet(
						pkg.NewLicenseFromLocations("GPL-1", file.NewLocation("/usr/share/doc/libpam-runtime/copyright")),
						pkg.NewLicenseFromLocations("GPL-2", file.NewLocation("/usr/share/doc/libpam-runtime/copyright")),
						pkg.NewLicenseFromLocations("LGPL-2.1", file.NewLocation("/usr/share/doc/libpam-runtime/copyright")),
					),
					Locations: file.NewLocationSet(
						file.NewLocation("/var/lib/dpkg/status"),
						file.NewLocation("/var/lib/dpkg/info/libpam-runtime.preinst"),
						file.NewLocation("/var/lib/dpkg/info/libpam-runtime.md5sums"),
						file.NewLocation("/var/lib/dpkg/info/libpam-runtime.conffiles"),
						file.NewLocation("/usr/share/doc/libpam-runtime/copyright"),
					),
					Type: pkg.DebPkg,
					Metadata: pkg.DpkgDBEntry{
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
						Depends: []string{
							"debconf (>= 0.5) | debconf-2.0",
							"debconf (>= 1.5.19) | cdebconf",
							"libpam-modules (>= 1.0.1-6)",
						},
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
					FoundBy: "dpkg-db-cataloger",
					Licenses: pkg.NewLicenseSet(
						pkg.NewLicenseFromLocations("public-domain", file.NewLocation("/usr/share/doc/libsqlite3-0/copyright")),
						pkg.NewLicenseFromLocations("GPL-2+", file.NewLocation("/usr/share/doc/libsqlite3-0/copyright")),
						pkg.NewLicenseFromLocations("GPL-2", file.NewLocation("/usr/share/doc/libsqlite3-0/copyright")),
					),
					Locations: file.NewLocationSet(
						file.NewLocation("/var/lib/dpkg/status.d/libsqlite3-0"),
						file.NewLocation("/var/lib/dpkg/status.d/libsqlite3-0.md5sums"),
						file.NewLocation("/var/lib/dpkg/status.d/libsqlite3-0.preinst"),
						file.NewLocation("/usr/share/doc/libsqlite3-0/copyright"),
					),
					Type: pkg.DebPkg,
					Metadata: pkg.DpkgDBEntry{
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
						Depends: []string{"libc6 (>= 2.29)"},
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
			c := NewDBCataloger()
			pkgtest.NewCatalogTester().
				WithImageResolver(t, tt.name).
				IgnoreLocationLayer(). // this fixture can be rebuilt, thus the layer ID will change
				Expects(tt.expected, nil).
				TestCataloger(t, c)
		})
	}
}

func Test_CatalogerRelationships(t *testing.T) {
	tests := []struct {
		name              string
		fixture           string
		wantRelationships map[string][]string
	}{
		{
			name:    "relationships for coreutils",
			fixture: "test-fixtures/var/lib/dpkg/status.d/coreutils-relationships",
			wantRelationships: map[string][]string{
				"coreutils":    {"libacl1", "libattr1", "libc6", "libgmp10", "libselinux1"},
				"libacl1":      {"libc6"},
				"libattr1":     {"libc6"},
				"libc6":        {"libgcc-s1"},
				"libgcc-s1":    {"gcc-12-base", "libc6"},
				"libgmp10":     {"libc6"},
				"libpcre2-8-0": {"libc6"},
				"libselinux1":  {"libc6", "libpcre2-8-0"},
			},
		},
		{
			name:    "relationships from dpkg example docs",
			fixture: "test-fixtures/var/lib/dpkg/status.d/doc-examples",
			wantRelationships: map[string][]string{
				"made-up-package-1": {"gnumach-dev", "hurd-dev", "kernel-headers-2.2.10"},
				"made-up-package-2": {"liblua5.1-dev", "libluajit5.1-dev"},
				"made-up-package-3": {"bar", "foo"},
				// note that the "made-up-package-4" depends on "made-up-package-5" but not via the direct
				// package name, but through the "provides" virtual package name "virtual-package-5".
				"made-up-package-4": {"made-up-package-5"},
				// note that though there is a "default-mta | mail-transport-agent | not-installed"
				// dependency choice we raise up the packages that are installed for every choice.
				// In this case that means that "default-mta" and "mail-transport-agent".
				"mutt": {"default-mta", "libc6", "mail-transport-agent"},
			},
		},
		{
			name:    "relationships for libpam-runtime",
			fixture: "test-fixtures/var/lib/dpkg/status.d/libpam-runtime",
			wantRelationships: map[string][]string{
				"libpam-runtime": {"cdebconf", "debconf-2.0", "debconf1", "debconf2", "libpam-modules"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkgs, relationships, err := NewDBCataloger().Catalog(context.Background(), file.NewMockResolverForPaths(tt.fixture))
			require.NotEmpty(t, pkgs)
			require.NotEmpty(t, relationships)
			require.NoError(t, err)

			if d := cmp.Diff(tt.wantRelationships, abstractRelationships(t, relationships)); d != "" {
				t.Errorf("unexpected relationships (-want +got):\n%s", d)
			}
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
				"usr/lib/dpkg/status",
				"var/lib/dpkg/status",
				"usr/lib/dpkg/status.d/pkg-1.0",
				"var/lib/dpkg/status.d/pkg-1.0",
				"usr/lib/opkg/info/pkg-1.0.control",
				"usr/lib/opkg/status",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				ExpectsResolverContentQueries(test.expected).
				TestCataloger(t, NewDBCataloger())
		})
	}
}
