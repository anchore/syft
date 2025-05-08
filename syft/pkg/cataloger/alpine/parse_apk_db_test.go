package alpine

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestExtraFileAttributes(t *testing.T) {
	tests := []struct {
		name     string
		expected pkg.ApkDBEntry
	}{
		{
			name: "test extra file attributes (checksum) are ignored",
			expected: pkg.ApkDBEntry{
				Files: []pkg.ApkFileRecord{
					{
						Path: "/usr",
					},
					{
						Path: "/usr/lib",
					},
					{
						Path: "/usr/lib/jvm",
					},
					{
						Path: "/usr/lib/jvm/java-1.8-openjdk",
					},
					{
						Path: "/usr/lib/jvm/java-1.8-openjdk/bin",
					},
					{
						Path:        "/usr/lib/jvm/java-1.8-openjdk/bin/policytool",
						OwnerUID:    "0",
						OwnerGID:    "0",
						Permissions: "755",
						Digest: &file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1M0C9qfC/+kdRiOodeihG2GMRtkE=",
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixturePath := "test-fixtures/extra-file-attributes"
			lrc := newLocationReadCloser(t, fixturePath)

			pkgs, _, err := parseApkDB(context.Background(), nil, new(generic.Environment), lrc)
			assert.NoError(t, err)
			require.Len(t, pkgs, 1)
			metadata := pkgs[0].Metadata.(pkg.ApkDBEntry)

			if diff := cmp.Diff(test.expected.Files, metadata.Files); diff != "" {
				t.Errorf("Files mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestSinglePackageDetails(t *testing.T) {
	tests := []struct {
		fixture  string
		expected pkg.Package
	}{
		{
			fixture: "test-fixtures/single",
			expected: pkg.Package{
				Name:    "musl-utils",
				Version: "1.1.24-r2",
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicense("MIT"),
					pkg.NewLicense("BSD"),
					pkg.NewLicense("GPL2+"),
				),
				Type: pkg.ApkPkg,
				Metadata: pkg.ApkDBEntry{
					Package:       "musl-utils",
					OriginPackage: "musl",
					Version:       "1.1.24-r2",
					Description:   "the musl c library (libc) implementation",
					Maintainer:    "Timo Teräs <timo.teras@iki.fi>",
					Architecture:  "x86_64",
					URL:           "https://musl.libc.org/",
					Size:          37944,
					InstalledSize: 151552,
					Dependencies:  []string{"scanelf", "so:libc.musl-x86_64.so.1"},
					Provides:      []string{"cmd:getconf", "cmd:getent", "cmd:iconv", "cmd:ldconfig", "cmd:ldd"},
					Checksum:      "Q1bTtF5526tETKfL+lnigzIDvm+2o=",
					GitCommit:     "4024cc3b29ad4c65544ad068b8f59172b5494306",
					Files: []pkg.ApkFileRecord{
						{
							Path: "/sbin",
						},
						{
							Path:        "/sbin/ldconfig",
							OwnerUID:    "0",
							OwnerGID:    "0",
							Permissions: "755",
							Digest: &file.Digest{
								Algorithm: "'Q1'+base64(sha1)",
								Value:     "Q1Kja2+POZKxEkUOZqwSjC6kmaED4=",
							},
						},
						{
							Path: "/usr",
						},
						{
							Path: "/usr/bin",
						},
						{
							Path:        "/usr/bin/iconv",
							OwnerUID:    "0",
							OwnerGID:    "0",
							Permissions: "755",
							Digest: &file.Digest{
								Algorithm: "'Q1'+base64(sha1)",
								Value:     "Q1CVmFbdY+Hv6/jAHl1gec2Kbx1EY=",
							},
						},
						{
							Path:        "/usr/bin/ldd",
							OwnerUID:    "0",
							OwnerGID:    "0",
							Permissions: "755",
							Digest: &file.Digest{
								Algorithm: "'Q1'+base64(sha1)",
								Value:     "Q1yFAhGggmL7ERgbIA7KQxyTzf3ks=",
							},
						},
						{
							Path:        "/usr/bin/getconf",
							OwnerUID:    "0",
							OwnerGID:    "0",
							Permissions: "755",
							Digest: &file.Digest{
								Algorithm: "'Q1'+base64(sha1)",
								Value:     "Q1dAdYK8M/INibRQF5B3Rw7cmNDDA=",
							},
						},
						{
							Path:        "/usr/bin/getent",
							OwnerUID:    "0",
							OwnerGID:    "0",
							Permissions: "755",
							Digest: &file.Digest{
								Algorithm: "'Q1'+base64(sha1)",
								Value:     "Q1eR2Dz/WylabgbWMTkd2+hGmEya4=",
							},
						},
					},
				},
			},
		},
		{
			fixture: "test-fixtures/empty-deps-and-provides",
			expected: pkg.Package{
				Name:    "alpine-baselayout-data",
				Version: "3.4.0-r0",
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicense("GPL-2.0-only"),
				),
				Type: pkg.ApkPkg,
				Metadata: pkg.ApkDBEntry{
					Package:       "alpine-baselayout-data",
					OriginPackage: "alpine-baselayout",
					Version:       "3.4.0-r0",
					Description:   "Alpine base dir structure and init scripts",
					Maintainer:    "Natanael Copa <ncopa@alpinelinux.org>",
					Architecture:  "x86_64",
					URL:           "https://git.alpinelinux.org/cgit/aports/tree/main/alpine-baselayout",
					Size:          11664,
					InstalledSize: 77824,
					Dependencies:  []string{},
					Provides:      []string{},
					Checksum:      "Q15ffjKT28lB7iSXjzpI/eDdYRCwM=",
					GitCommit:     "bd965a7ebf7fd8f07d7a0cc0d7375bf3e4eb9b24",
					Files: []pkg.ApkFileRecord{
						{Path: "/etc"},
						{Path: "/etc/fstab"},
						{Path: "/etc/group"},
						{Path: "/etc/hostname"},
						{Path: "/etc/hosts"},
						{Path: "/etc/inittab"},
						{Path: "/etc/modules"},
						{Path: "/etc/mtab", OwnerUID: "0", OwnerGID: "0", Permissions: "0777"},
						{Path: "/etc/nsswitch.conf"},
						{Path: "/etc/passwd"},
						{Path: "/etc/profile"},
						{Path: "/etc/protocols"},
						{Path: "/etc/services"},
						{Path: "/etc/shadow", OwnerUID: "0", OwnerGID: "148", Permissions: "0640"},
						{Path: "/etc/shells"},
						{Path: "/etc/sysctl.conf"},
					},
				},
			},
		},
		{
			fixture: "test-fixtures/base",
			expected: pkg.Package{
				Name:    "alpine-baselayout",
				Version: "3.2.0-r6",
				Licenses: pkg.NewLicenseSet(
					pkg.NewLicense("GPL-2.0-only"),
				),
				Type: pkg.ApkPkg,
				PURL: "",
				Metadata: pkg.ApkDBEntry{
					Package:       "alpine-baselayout",
					OriginPackage: "alpine-baselayout",
					Version:       "3.2.0-r6",
					Description:   "Alpine base dir structure and init scripts",
					Maintainer:    "Natanael Copa <ncopa@alpinelinux.org>",
					Architecture:  "x86_64",
					URL:           "https://git.alpinelinux.org/cgit/aports/tree/main/alpine-baselayout",
					Size:          19917,
					InstalledSize: 409600,
					Dependencies:  []string{"/bin/sh", "so:libc.musl-x86_64.so.1"},
					Provides:      []string{"cmd:mkmntdirs"},
					Checksum:      "Q1myMNfd7u5v5UTgNHeq1e31qTjZU=",
					GitCommit:     "e1c51734fa96fa4bac92e9f14a474324c67916fc",
					Files: []pkg.ApkFileRecord{
						{
							Path: "/dev",
						},
						{
							Path: "/dev/pts",
						},
						{
							Path: "/dev/shm",
						},
						{
							Path: "/etc",
						},
						{
							Path: "/etc/fstab",
							Digest: &file.Digest{
								Algorithm: "'Q1'+base64(sha1)",
								Value:     "Q11Q7hNe8QpDS531guqCdrXBzoA/o=",
							},
						},
						{
							Path: "/etc/group",
							Digest: &file.Digest{
								Algorithm: "'Q1'+base64(sha1)",
								Value:     "Q1oJ16xWudgKOrXIEquEDzlF2Lsm4=",
							},
						},
						{
							Path: "/etc/hostname",
							Digest: &file.Digest{
								Algorithm: "'Q1'+base64(sha1)",
								Value:     "Q16nVwYVXP/tChvUPdukVD2ifXOmc=",
							},
						},
						{
							Path: "/etc/hosts",
							Digest: &file.Digest{
								Algorithm: "'Q1'+base64(sha1)",
								Value:     "Q1BD6zJKZTRWyqGnPi4tSfd3krsMU=",
							},
						},
						{
							Path: "/etc/inittab",
							Digest: &file.Digest{
								Algorithm: "'Q1'+base64(sha1)",
								Value:     "Q1TsthbhW7QzWRe1E/NKwTOuD4pHc=",
							},
						},
						{
							Path: "/etc/modules",
							Digest: &file.Digest{
								Algorithm: "'Q1'+base64(sha1)",
								Value:     "Q1toogjUipHGcMgECgPJX64SwUT1M=",
							},
						},
						{
							Path: "/etc/motd",
							Digest: &file.Digest{
								Algorithm: "'Q1'+base64(sha1)",
								Value:     "Q1XmduVVNURHQ27TvYp1Lr5TMtFcA=",
							},
						},
						{
							Path:        "/etc/mtab",
							OwnerUID:    "0",
							OwnerGID:    "0",
							Permissions: "777",
							Digest: &file.Digest{
								Algorithm: "'Q1'+base64(sha1)",
								Value:     "Q1kiljhXXH1LlQroHsEJIkPZg2eiw=",
							},
						},
						{
							Path: "/etc/passwd",
							Digest: &file.Digest{
								Algorithm: "'Q1'+base64(sha1)",
								Value:     "Q1TchuuLUfur0izvfZQZxgN/LJhB8=",
							},
						},
						{
							Path: "/etc/profile",
							Digest: &file.Digest{
								Algorithm: "'Q1'+base64(sha1)",
								Value:     "Q1KpFb8kl5LvwXWlY3e58FNsjrI34=",
							},
						},
						{
							Path: "/etc/protocols",
							Digest: &file.Digest{
								Algorithm: "'Q1'+base64(sha1)",
								Value:     "Q13FqXUnvuOpMDrH/6rehxuYAEE34=",
							},
						},
						{
							Path: "/etc/services",
							Digest: &file.Digest{
								Algorithm: "'Q1'+base64(sha1)",
								Value:     "Q1C6HJNgQvLWqt5VY+n7MZJ1rsDuY=",
							},
						},
						{
							Path:        "/etc/shadow",
							OwnerUID:    "0",
							OwnerGID:    "42",
							Permissions: "640",
							Digest: &file.Digest{
								Algorithm: "'Q1'+base64(sha1)",
								Value:     "Q1ltrPIAW2zHeDiajsex2Bdmq3uqA=",
							},
						},
						{
							Path: "/etc/shells",
							Digest: &file.Digest{
								Algorithm: "'Q1'+base64(sha1)",
								Value:     "Q1ojm2YdpCJ6B/apGDaZ/Sdb2xJkA=",
							},
						},
						{
							Path: "/etc/sysctl.conf",
							Digest: &file.Digest{
								Algorithm: "'Q1'+base64(sha1)",
								Value:     "Q14upz3tfnNxZkIEsUhWn7Xoiw96g=",
							},
						},
						{
							Path: "/etc/apk",
						},
						{
							Path: "/etc/conf.d",
						},
						{
							Path: "/etc/crontabs",
						},
						{
							Path:        "/etc/crontabs/root",
							OwnerUID:    "0",
							OwnerGID:    "0",
							Permissions: "600",
							Digest: &file.Digest{
								Algorithm: "'Q1'+base64(sha1)",
								Value:     "Q1vfk1apUWI4yLJGhhNRd0kJixfvY=",
							},
						},
						{
							Path: "/etc/init.d",
						},
						{
							Path: "/etc/modprobe.d",
						},
						{
							Path: "/etc/modprobe.d/aliases.conf",
							Digest: &file.Digest{
								Algorithm: "'Q1'+base64(sha1)",
								Value:     "Q1WUbh6TBYNVK7e4Y+uUvLs/7viqk=",
							},
						},
						{
							Path: "/etc/modprobe.d/blacklist.conf",
							Digest: &file.Digest{
								Algorithm: "'Q1'+base64(sha1)",
								Value:     "Q1xxYGU6S6TLQvb7ervPrWWwAWqMg=",
							},
						},
						{
							Path: "/etc/modprobe.d/i386.conf",
							Digest: &file.Digest{
								Algorithm: "'Q1'+base64(sha1)",
								Value:     "Q1pnay/njn6ol9cCssL7KiZZ8etlc=",
							},
						},
						{
							Path: "/etc/modprobe.d/kms.conf",
							Digest: &file.Digest{
								Algorithm: "'Q1'+base64(sha1)",
								Value:     "Q1ynbLn3GYDpvajba/ldp1niayeog=",
							},
						},
						{
							Path: "/etc/modules-load.d",
						},
						{
							Path: "/etc/network",
						},
						{
							Path: "/etc/network/if-down.d",
						},
						{
							Path: "/etc/network/if-post-down.d",
						},
						{
							Path: "/etc/network/if-pre-up.d",
						},
						{
							Path: "/etc/network/if-up.d",
						},
						{
							Path: "/etc/opt",
						},
						{
							Path: "/etc/periodic",
						},
						{
							Path: "/etc/periodic/15min",
						},
						{
							Path: "/etc/periodic/daily",
						},
						{
							Path: "/etc/periodic/hourly",
						},
						{
							Path: "/etc/periodic/monthly",
						},
						{
							Path: "/etc/periodic/weekly",
						},
						{
							Path: "/etc/profile.d",
						},
						{
							Path: "/etc/profile.d/color_prompt",
							Digest: &file.Digest{
								Algorithm: "'Q1'+base64(sha1)",
								Value:     "Q10wL23GuSCVfumMRgakabUI6EsSk=",
							},
						},
						{
							Path: "/etc/profile.d/locale",
							Digest: &file.Digest{
								Algorithm: "'Q1'+base64(sha1)",
								Value:     "Q1R4bIEpnKxxOSrlnZy9AoawqZ5DU=",
							},
						},
						{
							Path: "/etc/sysctl.d",
						},
						{
							Path: "/home",
						},
						{
							Path: "/lib",
						},
						{
							Path: "/lib/firmware",
						},
						{
							Path: "/lib/mdev",
						},
						{
							Path: "/lib/modules-load.d",
						},
						{
							Path: "/lib/sysctl.d",
						},
						{
							Path: "/lib/sysctl.d/00-alpine.conf",
							Digest: &file.Digest{
								Algorithm: "'Q1'+base64(sha1)",
								Value:     "Q1HpElzW1xEgmKfERtTy7oommnq6c=",
							},
						},
						{
							Path: "/media",
						},
						{
							Path: "/media/cdrom",
						},
						{
							Path: "/media/floppy",
						},
						{
							Path: "/media/usb",
						},
						{
							Path: "/mnt",
						},
						{
							Path: "/opt",
						},
						{
							Path: "/proc",
						},
						{
							Path:        "/root",
							OwnerUID:    "0",
							OwnerGID:    "0",
							Permissions: "700",
						},
						{
							Path: "/run",
						},
						{
							Path: "/sbin",
						},
						{
							Path:        "/sbin/mkmntdirs",
							OwnerUID:    "0",
							OwnerGID:    "0",
							Permissions: "755",
							Digest: &file.Digest{
								Algorithm: "'Q1'+base64(sha1)",
								Value:     "Q1YeuSmC7iDbEWrusPzA/zUQF6YSg=",
							},
						},
						{
							Path: "/srv",
						},
						{
							Path: "/sys",
						},
						{
							Path:        "/tmp",
							OwnerUID:    "0",
							OwnerGID:    "0",
							Permissions: "1777",
						},
						{
							Path: "/usr",
						},
						{
							Path: "/usr/lib",
						},
						{
							Path: "/usr/lib/modules-load.d",
						},
						{
							Path: "/usr/local",
						},
						{
							Path: "/usr/local/bin",
						},
						{
							Path: "/usr/local/lib",
						},
						{
							Path: "/usr/local/share",
						},
						{
							Path: "/usr/sbin",
						},
						{
							Path: "/usr/share",
						},
						{
							Path: "/usr/share/man",
						},
						{
							Path: "/usr/share/misc",
						},
						{
							Path: "/var",
						},
						{
							Path:        "/var/run",
							OwnerUID:    "0",
							OwnerGID:    "0",
							Permissions: "777",
							Digest: &file.Digest{
								Algorithm: "'Q1'+base64(sha1)",
								Value:     "Q11/SNZz/8cK2dSKK+cJpVrZIuF4Q=",
							},
						},
						{
							Path: "/var/cache",
						},
						{
							Path: "/var/cache/misc",
						},
						{
							Path:        "/var/empty",
							OwnerUID:    "0",
							OwnerGID:    "0",
							Permissions: "555",
						},
						{
							Path: "/var/lib",
						},
						{
							Path: "/var/lib/misc",
						},
						{
							Path: "/var/local",
						},
						{
							Path: "/var/lock",
						},
						{
							Path: "/var/lock/subsys",
						},
						{
							Path: "/var/log",
						},
						{
							Path: "/var/mail",
						},
						{
							Path: "/var/opt",
						},
						{
							Path: "/var/spool",
						},
						{
							Path:        "/var/spool/mail",
							OwnerUID:    "0",
							OwnerGID:    "0",
							Permissions: "777",
							Digest: &file.Digest{
								Algorithm: "'Q1'+base64(sha1)",
								Value:     "Q1dzbdazYZA2nTzSIG3YyNw7d4Juc=",
							},
						},
						{
							Path: "/var/spool/cron",
						},
						{
							Path:        "/var/spool/cron/crontabs",
							OwnerUID:    "0",
							OwnerGID:    "0",
							Permissions: "777",
							Digest: &file.Digest{
								Algorithm: "'Q1'+base64(sha1)",
								Value:     "Q1OFZt+ZMp7j0Gny0rqSKuWJyqYmA=",
							},
						},
						{
							Path:        "/var/tmp",
							OwnerUID:    "0",
							OwnerGID:    "0",
							Permissions: "1777",
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			fixtureLocation := file.NewLocation(test.fixture)
			test.expected.Locations = file.NewLocationSet(fixtureLocation)
			licenses := test.expected.Licenses.ToSlice()
			for i := range licenses {
				licenses[i].Locations.Add(fixtureLocation)
			}
			test.expected.Licenses = pkg.NewLicenseSet(licenses...)
			pkgtest.TestFileParser(t, test.fixture, parseApkDB, []pkg.Package{test.expected}, nil)
		})
	}
}

func Test_processChecksum(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  file.Digest
	}{
		{
			name:  "md5",
			value: "38870ede8700535d7382ff66a46fcc2f",
			want: file.Digest{
				Algorithm: "md5",
				Value:     "38870ede8700535d7382ff66a46fcc2f",
			},
		},
		{
			name:  "sha1",
			value: "Q1Kja2+POZKxEkUOZqwSjC6kmaED4=",
			want: file.Digest{
				Algorithm: "'Q1'+base64(sha1)",
				Value:     "Q1Kja2+POZKxEkUOZqwSjC6kmaED4=",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, &test.want, processChecksum(test.value))
		})
	}
}

func Test_parseApkDB_expectedPkgNames(t *testing.T) {
	tests := []struct {
		fixture      string
		wantPkgNames []string
		wantErr      assert.ErrorAssertionFunc
	}{
		{
			fixture: "very-large-entries",
			wantPkgNames: []string{
				"ca-certificates-bundle",
				"glibc-locale-posix",
				"wolfi-baselayout",
				"glibc",
				"libcrypto3",
				"libssl3",
				"zlib",
				"apk-tools",
				"ncurses-terminfo-base",
				"ncurses",
				"bash",
				"libcap",
				"bubblewrap",
				"busybox",
				"libbrotlicommon1",
				"libbrotlidec1",
				"libnghttp2-14",
				"libcurl4",
				"curl",
				"expat",
				"libpcre2-8-0",
				"git",
				"binutils",
				"libstdc++-dev",
				"libgcc",
				"libstdc++",
				"gmp",
				"isl",
				"mpfr",
				"mpc",
				"gcc",
				"linux-headers",
				"glibc-dev",
				"make",
				"pkgconf",
				"build-base",
				"go",
				"tree",
				"sdk",
			},
			wantErr: assert.NoError,
		},
	}

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			fixturePath := filepath.Join("test-fixtures", test.fixture)
			lrc := newLocationReadCloser(t, fixturePath)

			pkgs, _, err := parseApkDB(context.Background(), nil, new(generic.Environment), lrc)
			test.wantErr(t, err)

			names := toPackageNames(pkgs)
			if diff := cmp.Diff(test.wantPkgNames, names); diff != "" {
				t.Errorf("Packages mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func toPackageNames(pkgs []pkg.Package) []string {
	names := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		names = append(names, p.Name)
	}

	return names
}

func newLocationReadCloser(t *testing.T, path string) file.LocationReadCloser {
	f, err := os.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { f.Close() })

	return file.NewLocationReadCloser(file.NewLocation(path), f)
}

func TestParseReleasesFromAPKRepository(t *testing.T) {
	tests := []struct {
		repos string
		want  []linux.Release
		desc  string
	}{
		{
			"https://foo.alpinelinux.org/alpine/v3.14/main",
			[]linux.Release{
				{Name: "Alpine Linux", ID: "alpine", VersionID: "3.14"},
			},
			"single repo",
		},
		{
			`https://foo.alpinelinux.org/alpine/v3.14/main
https://foo.alpinelinux.org/alpine/v3.14/community`,
			[]linux.Release{
				{Name: "Alpine Linux", ID: "alpine", VersionID: "3.14"},
				{Name: "Alpine Linux", ID: "alpine", VersionID: "3.14"},
			},
			"multiple repos",
		},
		{
			``,
			nil,
			"empty",
		},
		{
			`https://foo.bar.org/alpine/v3.14/main
https://foo.them.org/alpine/v3.14/community`,
			nil,
			"invalid repos",
		},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			reposReader := io.NopCloser(strings.NewReader(tt.repos))
			got := parseReleasesFromAPKRepository(file.LocationReadCloser{
				Location:   file.NewLocation("test"),
				ReadCloser: reposReader,
			})
			assert.Equal(t, tt.want, got)
		})
	}
}
