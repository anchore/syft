package apkdb

import (
	"bufio"
	"os"
	"testing"

	"github.com/anchore/syft/syft/file"

	"github.com/go-test/deep"

	"github.com/anchore/syft/syft/pkg"
)

func TestExtraFileAttributes(t *testing.T) {
	tests := []struct {
		name     string
		expected pkg.ApkMetadata
	}{
		{
			name: "test extra file attributes (checksum) are ignored",
			expected: pkg.ApkMetadata{
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
							Algorithm: "sha1",
							Value:     "Q1M0C9qfC/+kdRiOodeihG2GMRtkE=",
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			file, err := os.Open("test-fixtures/extra-file-attributes")
			if err != nil {
				t.Fatal("Unable to read test-fixtures/extra-file-attributes: ", err)
			}
			defer func() {
				err := file.Close()
				if err != nil {
					t.Fatal("closing file failed:", err)
				}
			}()

			reader := bufio.NewReader(file)

			entry, err := parseApkDBEntry(reader)
			if err != nil {
				t.Fatal("Unable to read file contents: ", err)
			}

			if diff := deep.Equal(entry.Files, test.expected.Files); diff != nil {
				for _, d := range diff {
					t.Errorf("diff: %+v", d)
				}
			}
		})
	}
}

func TestSinglePackageDetails(t *testing.T) {
	tests := []struct {
		fixture  string
		expected pkg.ApkMetadata
	}{
		{
			fixture: "test-fixtures/single",
			expected: pkg.ApkMetadata{
				Package:          "musl-utils",
				OriginPackage:    "musl",
				Version:          "1.1.24-r2",
				Description:      "the musl c library (libc) implementation",
				Maintainer:       "Timo Teräs <timo.teras@iki.fi>",
				License:          "MIT BSD GPL2+",
				Architecture:     "x86_64",
				URL:              "https://musl.libc.org/",
				Size:             37944,
				InstalledSize:    151552,
				PullDependencies: "scanelf so:libc.musl-x86_64.so.1",
				PullChecksum:     "Q1bTtF5526tETKfL+lnigzIDvm+2o=",
				GitCommitOfAport: "4024cc3b29ad4c65544ad068b8f59172b5494306",
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
							Algorithm: "sha1",
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
							Algorithm: "sha1",
							Value:     "Q1CVmFbdY+Hv6/jAHl1gec2Kbx1EY=",
						},
					},
					{
						Path:        "/usr/bin/ldd",
						OwnerUID:    "0",
						OwnerGID:    "0",
						Permissions: "755",
						Digest: &file.Digest{
							Algorithm: "sha1",
							Value:     "Q1yFAhGggmL7ERgbIA7KQxyTzf3ks=",
						},
					},
					{
						Path:        "/usr/bin/getconf",
						OwnerUID:    "0",
						OwnerGID:    "0",
						Permissions: "755",
						Digest: &file.Digest{
							Algorithm: "sha1",
							Value:     "Q1dAdYK8M/INibRQF5B3Rw7cmNDDA=",
						},
					},
					{
						Path:        "/usr/bin/getent",
						OwnerUID:    "0",
						OwnerGID:    "0",
						Permissions: "755",
						Digest: &file.Digest{
							Algorithm: "sha1",
							Value:     "Q1eR2Dz/WylabgbWMTkd2+hGmEya4=",
						},
					},
				},
			},
		},
		{
			fixture: "test-fixtures/base",
			expected: pkg.ApkMetadata{
				Package:          "alpine-baselayout",
				OriginPackage:    "alpine-baselayout",
				Version:          "3.2.0-r6",
				Description:      "Alpine base dir structure and init scripts",
				Maintainer:       "Natanael Copa <ncopa@alpinelinux.org>",
				License:          "GPL-2.0-only",
				Architecture:     "x86_64",
				URL:              "https://git.alpinelinux.org/cgit/aports/tree/main/alpine-baselayout",
				Size:             19917,
				InstalledSize:    409600,
				PullDependencies: "/bin/sh so:libc.musl-x86_64.so.1",
				PullChecksum:     "Q1myMNfd7u5v5UTgNHeq1e31qTjZU=",
				GitCommitOfAport: "e1c51734fa96fa4bac92e9f14a474324c67916fc",
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
							Algorithm: "sha1",
							Value:     "Q11Q7hNe8QpDS531guqCdrXBzoA/o=",
						},
					},
					{
						Path: "/etc/group",
						Digest: &file.Digest{
							Algorithm: "sha1",
							Value:     "Q1oJ16xWudgKOrXIEquEDzlF2Lsm4=",
						},
					},
					{
						Path: "/etc/hostname",
						Digest: &file.Digest{
							Algorithm: "sha1",
							Value:     "Q16nVwYVXP/tChvUPdukVD2ifXOmc=",
						},
					},
					{
						Path: "/etc/hosts",
						Digest: &file.Digest{
							Algorithm: "sha1",
							Value:     "Q1BD6zJKZTRWyqGnPi4tSfd3krsMU=",
						},
					},
					{
						Path: "/etc/inittab",
						Digest: &file.Digest{
							Algorithm: "sha1",
							Value:     "Q1TsthbhW7QzWRe1E/NKwTOuD4pHc=",
						},
					},
					{
						Path: "/etc/modules",
						Digest: &file.Digest{
							Algorithm: "sha1",
							Value:     "Q1toogjUipHGcMgECgPJX64SwUT1M=",
						},
					},
					{
						Path: "/etc/motd",
						Digest: &file.Digest{
							Algorithm: "sha1",
							Value:     "Q1XmduVVNURHQ27TvYp1Lr5TMtFcA=",
						},
					},
					{
						Path:        "/etc/mtab",
						OwnerUID:    "0",
						OwnerGID:    "0",
						Permissions: "777",
						Digest: &file.Digest{
							Algorithm: "sha1",
							Value:     "Q1kiljhXXH1LlQroHsEJIkPZg2eiw=",
						},
					},
					{
						Path: "/etc/passwd",
						Digest: &file.Digest{
							Algorithm: "sha1",
							Value:     "Q1TchuuLUfur0izvfZQZxgN/LJhB8=",
						},
					},
					{
						Path: "/etc/profile",
						Digest: &file.Digest{
							Algorithm: "sha1",
							Value:     "Q1KpFb8kl5LvwXWlY3e58FNsjrI34=",
						},
					},
					{
						Path: "/etc/protocols",
						Digest: &file.Digest{
							Algorithm: "sha1",
							Value:     "Q13FqXUnvuOpMDrH/6rehxuYAEE34=",
						},
					},
					{
						Path: "/etc/services",
						Digest: &file.Digest{
							Algorithm: "sha1",
							Value:     "Q1C6HJNgQvLWqt5VY+n7MZJ1rsDuY=",
						},
					},
					{
						Path:        "/etc/shadow",
						OwnerUID:    "0",
						OwnerGID:    "42",
						Permissions: "640",
						Digest: &file.Digest{
							Algorithm: "sha1",
							Value:     "Q1ltrPIAW2zHeDiajsex2Bdmq3uqA=",
						},
					},
					{
						Path: "/etc/shells",
						Digest: &file.Digest{
							Algorithm: "sha1",
							Value:     "Q1ojm2YdpCJ6B/apGDaZ/Sdb2xJkA=",
						},
					},
					{
						Path: "/etc/sysctl.conf",
						Digest: &file.Digest{
							Algorithm: "sha1",
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
							Algorithm: "sha1",
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
							Algorithm: "sha1",
							Value:     "Q1WUbh6TBYNVK7e4Y+uUvLs/7viqk=",
						},
					},
					{
						Path: "/etc/modprobe.d/blacklist.conf",
						Digest: &file.Digest{
							Algorithm: "sha1",
							Value:     "Q1xxYGU6S6TLQvb7ervPrWWwAWqMg=",
						},
					},
					{
						Path: "/etc/modprobe.d/i386.conf",
						Digest: &file.Digest{
							Algorithm: "sha1",
							Value:     "Q1pnay/njn6ol9cCssL7KiZZ8etlc=",
						},
					},
					{
						Path: "/etc/modprobe.d/kms.conf",
						Digest: &file.Digest{
							Algorithm: "sha1",
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
							Algorithm: "sha1",
							Value:     "Q10wL23GuSCVfumMRgakabUI6EsSk=",
						},
					},
					{
						Path: "/etc/profile.d/locale",
						Digest: &file.Digest{
							Algorithm: "sha1",
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
							Algorithm: "sha1",
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
							Algorithm: "sha1",
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
							Algorithm: "sha1",
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
							Algorithm: "sha1",
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
							Algorithm: "sha1",
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
	}

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			file, err := os.Open(test.fixture)
			if err != nil {
				t.Fatal("Unable to read fixture: ", err)
			}
			defer func() {
				err := file.Close()
				if err != nil {
					t.Fatal("closing file failed:", err)
				}
			}()

			reader := bufio.NewReader(file)

			entry, err := parseApkDBEntry(reader)
			if err != nil {
				t.Fatal("Unable to read file contents: ", err)
			}

			if diff := deep.Equal(*entry, test.expected); diff != nil {
				for _, d := range diff {
					t.Errorf("diff: %+v", d)
				}
			}
		})
	}
}

func TestMultiplePackages(t *testing.T) {
	tests := []struct {
		fixture  string
		expected []*pkg.Package
	}{
		{
			fixture: "test-fixtures/multiple",
			expected: []*pkg.Package{
				{
					Name:         "libc-utils",
					Version:      "0.7.2-r0",
					Licenses:     []string{"BSD"},
					Type:         pkg.ApkPkg,
					MetadataType: pkg.ApkMetadataType,
					Metadata: pkg.ApkMetadata{
						Package:          "libc-utils",
						OriginPackage:    "libc-dev",
						Maintainer:       "Natanael Copa <ncopa@alpinelinux.org>",
						Version:          "0.7.2-r0",
						License:          "BSD",
						Architecture:     "x86_64",
						URL:              "http://alpinelinux.org",
						Description:      "Meta package to pull in correct libc",
						Size:             1175,
						InstalledSize:    4096,
						PullChecksum:     "Q1p78yvTLG094tHE1+dToJGbmYzQE=",
						GitCommitOfAport: "97b1c2842faa3bfa30f5811ffbf16d5ff9f1a479",
						PullDependencies: "musl-utils",
						Files:            []pkg.ApkFileRecord{},
					},
				},
				{
					Name:         "musl-utils",
					Version:      "1.1.24-r2",
					Licenses:     []string{"MIT", "BSD", "GPL2+"},
					Type:         pkg.ApkPkg,
					MetadataType: pkg.ApkMetadataType,
					Metadata: pkg.ApkMetadata{
						Package:          "musl-utils",
						OriginPackage:    "musl",
						Version:          "1.1.24-r2",
						Description:      "the musl c library (libc) implementation",
						Maintainer:       "Timo Teräs <timo.teras@iki.fi>",
						License:          "MIT BSD GPL2+",
						Architecture:     "x86_64",
						URL:              "https://musl.libc.org/",
						Size:             37944,
						InstalledSize:    151552,
						PullDependencies: "scanelf so:libc.musl-x86_64.so.1",
						PullChecksum:     "Q1bTtF5526tETKfL+lnigzIDvm+2o=",
						GitCommitOfAport: "4024cc3b29ad4c65544ad068b8f59172b5494306",
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
									Algorithm: "sha1",
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
									Algorithm: "sha1",
									Value:     "Q1CVmFbdY+Hv6/jAHl1gec2Kbx1EY=",
								},
							},
							{
								Path:        "/usr/bin/ldd",
								OwnerUID:    "0",
								OwnerGID:    "0",
								Permissions: "755",
								Digest: &file.Digest{
									Algorithm: "sha1",
									Value:     "Q1yFAhGggmL7ERgbIA7KQxyTzf3ks=",
								},
							},
							{
								Path:        "/usr/bin/getconf",
								OwnerUID:    "0",
								OwnerGID:    "0",
								Permissions: "755",
								Digest: &file.Digest{
									Algorithm: "sha1",
									Value:     "Q1dAdYK8M/INibRQF5B3Rw7cmNDDA=",
								},
							},
							{
								Path:        "/usr/bin/getent",
								OwnerUID:    "0",
								OwnerGID:    "0",
								Permissions: "755",
								Digest: &file.Digest{
									Algorithm: "sha1",
									Value:     "Q1eR2Dz/WylabgbWMTkd2+hGmEya4=",
								},
							},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			file, err := os.Open(test.fixture)
			if err != nil {
				t.Fatal("Unable to read: ", err)
			}
			defer func() {
				err := file.Close()
				if err != nil {
					t.Fatal("closing file failed:", err)
				}
			}()

			// TODO: no relationships are under test yet
			pkgs, _, err := parseApkDB(file.Name(), file)
			if err != nil {
				t.Fatal("Unable to read file contents: ", err)
			}

			if len(pkgs) != 2 {
				t.Fatalf("unexpected number of entries: %d", len(pkgs))
			}

			for idx, entry := range pkgs {
				if diff := deep.Equal(entry, test.expected[idx]); diff != nil {
					for _, d := range diff {
						t.Errorf("diff: %+v", d)
					}
				}
			}

		})
	}
}
