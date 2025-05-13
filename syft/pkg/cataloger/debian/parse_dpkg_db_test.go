package debian

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func Test_parseDpkgStatus(t *testing.T) {
	tests := []struct {
		name        string
		expected    []pkg.DpkgDBEntry
		fixturePath string
	}{
		{
			name:        "single package",
			fixturePath: "test-fixtures/var/lib/dpkg/status.d/single",
			expected: []pkg.DpkgDBEntry{
				{
					Package:       "apt",
					Source:        "apt-dev",
					Version:       "1.8.2",
					Architecture:  "amd64",
					InstalledSize: 4064,
					Maintainer:    "APT Development Team <deity@lists.debian.org>",
					Description: `commandline package manager
 This package provides commandline tools for searching and
 managing as well as querying information about packages
 as a low-level access to all features of the libapt-pkg library.
 .
 These include:
 * apt-get for retrieval of packages and information about them
 from authenticated sources and for installation, upgrade and
 removal of packages together with their dependencies
 * apt-cache for querying available information about installed
 as well as installable packages
 * apt-cdrom to use removable media as a source for packages
 * apt-config as an interface to the configuration settings
 * apt-key as an interface to manage authentication keys`,
					Provides: []string{"apt-transport-https (= 1.8.2)"},
					Depends: []string{
						"adduser",
						"gpgv | gpgv2 | gpgv1",
						"debian-archive-keyring",
						"libapt-pkg5.0 (>= 1.7.0~alpha3~)",
						"libc6 (>= 2.15)",
						"libgcc1 (>= 1:3.0)",
						"libgnutls30 (>= 3.6.6)",
						"libseccomp2 (>= 1.0.1)",
						"libstdc++6 (>= 5.2)",
					},
					Files: []pkg.DpkgFileRecord{
						{
							Path: "/etc/apt/apt.conf.d/01autoremove",
							Digest: &file.Digest{
								Algorithm: "md5",
								Value:     "76120d358bc9037bb6358e737b3050b5",
							},
							IsConfigFile: true,
						},
						{
							Path: "/etc/cron.daily/apt-compat",
							Digest: &file.Digest{
								Algorithm: "md5",
								Value:     "49e9b2cfa17849700d4db735d04244f3",
							},
							IsConfigFile: true,
						},
						{
							Path: "/etc/kernel/postinst.d/apt-auto-removal",
							Digest: &file.Digest{
								Algorithm: "md5",
								Value:     "4ad976a68f045517cf4696cec7b8aa3a",
							},
							IsConfigFile: true,
						},
						{
							Path: "/etc/logrotate.d/apt",
							Digest: &file.Digest{
								Algorithm: "md5",
								Value:     "179f2ed4f85cbaca12fa3d69c2a4a1c3",
							},
							IsConfigFile: true,
						},
					},
				},
			},
		},
		{
			name:        "single package with installed size",
			fixturePath: "test-fixtures/var/lib/dpkg/status.d/installed-size-4KB",
			expected: []pkg.DpkgDBEntry{
				{
					Package:       "apt",
					Source:        "apt-dev",
					Version:       "1.8.2",
					Architecture:  "amd64",
					InstalledSize: 4000,
					Maintainer:    "APT Development Team <deity@lists.debian.org>",
					Description: `commandline package manager
 This package provides commandline tools for searching and
 managing as well as querying information about packages
 as a low-level access to all features of the libapt-pkg library.
 .
 These include:
 * apt-get for retrieval of packages and information about them
 from authenticated sources and for installation, upgrade and
 removal of packages together with their dependencies
 * apt-cache for querying available information about installed
 as well as installable packages
 * apt-cdrom to use removable media as a source for packages
 * apt-config as an interface to the configuration settings
 * apt-key as an interface to manage authentication keys`,
					Provides: []string{"apt-transport-https (= 1.8.2)"},
					Depends: []string{
						"adduser",
						"gpgv | gpgv2 | gpgv1",
						"debian-archive-keyring",
						"libapt-pkg5.0 (>= 1.7.0~alpha3~)",
						"libc6 (>= 2.15)",
						"libgcc1 (>= 1:3.0)",
						"libgnutls30 (>= 3.6.6)",
						"libseccomp2 (>= 1.0.1)",
						"libstdc++6 (>= 5.2)",
					},
					Files: []pkg.DpkgFileRecord{},
				},
			},
		},
		{
			name:        "multiple entries",
			fixturePath: "test-fixtures/var/lib/dpkg/status.d/multiple",
			expected: []pkg.DpkgDBEntry{
				{
					Package: "no-version",
					Files:   []pkg.DpkgFileRecord{},
				},
				{
					Package:       "tzdata",
					Version:       "2020a-0+deb10u1",
					Source:        "tzdata-dev",
					Architecture:  "all",
					InstalledSize: 3036,
					Maintainer:    "GNU Libc Maintainers <debian-glibc@lists.debian.org>",
					Description: `time zone and daylight-saving time data
 This package contains data required for the implementation of
 standard local time for many representative locations around the
 globe. It is updated periodically to reflect changes made by
 political bodies to time zone boundaries, UTC offsets, and
 daylight-saving rules.`,
					Provides: []string{"tzdata-buster"},
					Depends:  []string{"debconf (>= 0.5) | debconf-2.0"},
					Files:    []pkg.DpkgFileRecord{},
				},
				{
					Package:       "util-linux",
					Version:       "2.33.1-0.1",
					Architecture:  "amd64",
					InstalledSize: 4327,
					Maintainer:    "LaMont Jones <lamont@debian.org>",
					Description: `miscellaneous system utilities
 This package contains a number of important utilities, most of which
 are oriented towards maintenance of your system. Some of the more
 important utilities included in this package allow you to view kernel
 messages, create new filesystems, view block device information,
 interface with real time clock, etc.`,
					Depends: []string{"fdisk", "login (>= 1:4.5-1.1~)"},
					PreDepends: []string{
						"libaudit1 (>= 1:2.2.1)", "libblkid1 (>= 2.31.1)", "libc6 (>= 2.25)",
						"libcap-ng0 (>= 0.7.9)", "libmount1 (>= 2.25)", "libpam0g (>= 0.99.7.1)",
						"libselinux1 (>= 2.6-3~)", "libsmartcols1 (>= 2.33)", "libsystemd0",
						"libtinfo6 (>= 6)", "libudev1 (>= 183)", "libuuid1 (>= 2.16)",
						"zlib1g (>= 1:1.1.4)",
					},
					Files: []pkg.DpkgFileRecord{
						{
							Path: "/etc/default/hwclock",
							Digest: &file.Digest{
								Algorithm: "md5",
								Value:     "3916544450533eca69131f894db0ca12",
							},
							IsConfigFile: true,
						},
						{
							Path: "/etc/init.d/hwclock.sh",
							Digest: &file.Digest{
								Algorithm: "md5",
								Value:     "1ca5c0743fa797ffa364db95bb8d8d8e",
							},
							IsConfigFile: true,
						},
						{
							Path: "/etc/pam.d/runuser",
							Digest: &file.Digest{
								Algorithm: "md5",
								Value:     "b8b44b045259525e0fae9e38fdb2aeeb",
							},
							IsConfigFile: true,
						},
						{
							Path: "/etc/pam.d/runuser-l",
							Digest: &file.Digest{
								Algorithm: "md5",
								Value:     "2106ea05877e8913f34b2c77fa02be45",
							},
							IsConfigFile: true,
						},
						{
							Path: "/etc/pam.d/su",
							Digest: &file.Digest{
								Algorithm: "md5",
								Value:     "ce6dcfda3b190a27a455bb38a45ff34a",
							},
							IsConfigFile: true,
						},
						{
							Path: "/etc/pam.d/su-l",
							Digest: &file.Digest{
								Algorithm: "md5",
								Value:     "756fef5687fecc0d986e5951427b0c4f",
							},
							IsConfigFile: true,
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f, err := os.Open(test.fixturePath)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, f.Close()) })

			reader := bufio.NewReader(f)

			entries, err := parseDpkgStatus(reader)
			require.NoError(t, err)

			if diff := cmp.Diff(test.expected, entries); diff != "" {
				t.Errorf("unexpected entry (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_corruptEntry(t *testing.T) {
	f, err := os.Open("test-fixtures/var/lib/dpkg/status.d/corrupt")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, f.Close()) })

	reader := bufio.NewReader(f)

	_, err = parseDpkgStatus(reader)
	require.Error(t, err)
}

func TestSourceVersionExtract(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "name and version",
			input:    "test (1.2.3)",
			expected: []string{"test", "1.2.3"},
		},
		{
			name:     "only name",
			input:    "test",
			expected: []string{"test", ""},
		},
		{
			name:     "empty",
			input:    "",
			expected: []string{"", ""},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			name, version := extractSourceVersion(test.input)

			if name != test.expected[0] {
				t.Errorf("mismatch name for %q : %q!=%q", test.input, name, test.expected[0])
			}

			if version != test.expected[1] {
				t.Errorf("mismatch version for %q : %q!=%q", test.input, version, test.expected[1])
			}

		})
	}
}

func requireAs(expected error) require.ErrorAssertionFunc {
	return func(t require.TestingT, err error, i ...interface{}) {
		require.ErrorAs(t, err, &expected)
	}
}

func Test_parseDpkgStatus_negativeCases(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []pkg.Package
		wantErr require.ErrorAssertionFunc
	}{
		{
			name:    "no more packages",
			input:   `Package: apt`,
			wantErr: requireAs(errors.New("unable to determine packages")),
		},
		{
			name: "duplicated key",
			input: `Package: apt
Package: apt-get

`,
			wantErr: requireAs(errors.New("duplicate key discovered: Package")),
		},
		{
			name: "no match for continuation",
			input: `  Package: apt

`,
			wantErr: requireAs(errors.New("no match for continuation: line: '  Package: apt'")),
		},
		{
			name: "find keys",
			input: `Package: apt
Status: install ok installed
Installed-Size: 10kib

`,
			want: []pkg.Package{
				{
					Name:      "apt",
					Type:      "deb",
					PURL:      "pkg:deb/debian/apt?distro=debian-10",
					Licenses:  pkg.NewLicenseSet(),
					Locations: file.NewLocationSet(file.NewLocation("place")),
					Metadata: pkg.DpkgDBEntry{
						Package:       "apt",
						InstalledSize: 10240,
						Files:         []pkg.DpkgFileRecord{},
					},
				},
			},
			wantErr: require.NoError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromString("place", tt.input).
				WithErrorAssertion(tt.wantErr).
				WithLinuxRelease(linux.Release{ID: "debian", VersionID: "10"}).
				Expects(tt.want, nil).
				TestParser(t, parseDpkgDB)
		})
	}
}

func Test_handleNewKeyValue(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		wantKey string
		wantVal interface{}
		wantErr require.ErrorAssertionFunc
	}{
		{
			name:    "cannot parse field",
			line:    "blabla",
			wantErr: requireAs(errors.New("cannot parse field from line: 'blabla'")),
		},
		{
			name:    "parse field",
			line:    "key: val",
			wantKey: "key",
			wantVal: "val",
			wantErr: require.NoError,
		},
		{
			name:    "parse installed size",
			line:    "InstalledSize: 128",
			wantKey: "InstalledSize",
			wantVal: 128,
			wantErr: require.NoError,
		},
		{
			name:    "parse installed kib size",
			line:    "InstalledSize: 1kib",
			wantKey: "InstalledSize",
			wantVal: 1024,
			wantErr: require.NoError,
		},
		{
			name:    "parse installed kb size",
			line:    "InstalledSize: 1kb",
			wantKey: "InstalledSize",
			wantVal: 1000,
			wantErr: require.NoError,
		},
		{
			name:    "parse installed-size mb",
			line:    "Installed-Size: 1 mb",
			wantKey: "InstalledSize",
			wantVal: 1000000,
			wantErr: require.NoError,
		},
		{
			name:    "fail parsing installed-size",
			line:    "Installed-Size: 1bla",
			wantKey: "",
			wantErr: requireAs(fmt.Errorf("unhandled size name: %s", "bla")),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, gotVal, err := handleNewKeyValue(tt.line)
			tt.wantErr(t, err, fmt.Sprintf("handleNewKeyValue(%v)", tt.line))

			assert.Equalf(t, tt.wantKey, gotKey, "handleNewKeyValue(%v)", tt.line)
			assert.Equalf(t, tt.wantVal, gotVal, "handleNewKeyValue(%v)", tt.line)
		})
	}
}

func abstractRelationships(t testing.TB, relationships []artifact.Relationship) map[string][]string {
	t.Helper()

	abstracted := make(map[string][]string)
	for _, relationship := range relationships {
		fromPkg, ok := relationship.From.(pkg.Package)
		if !ok {
			continue
		}
		toPkg, ok := relationship.To.(pkg.Package)
		if !ok {
			continue
		}

		// we build this backwards since we use DependencyOfRelationship instead of DependsOn
		abstracted[toPkg.Name] = append(abstracted[toPkg.Name], fromPkg.Name)
	}

	return abstracted
}
