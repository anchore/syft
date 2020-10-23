package apkdb

import (
	"bufio"
	"os"
	"testing"

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
						Path:        "/usr/lib/jvm/java-1.8-openjdk/bin/policytool",
						OwnerUID:    "0",
						OwnerGUI:    "0",
						Permissions: "755",
						Checksum:    "Q1M0C9qfC/+kdRiOodeihG2GMRtkE=",
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

func TestSinglePackage(t *testing.T) {
	tests := []struct {
		name     string
		expected pkg.ApkMetadata
	}{
		{
			name: "Test Single Package",
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
						Path:        "/sbin/ldconfig",
						OwnerUID:    "0",
						OwnerGUI:    "0",
						Permissions: "755",
						Checksum:    "Q1Kja2+POZKxEkUOZqwSjC6kmaED4=",
					},
					{
						Path:        "/usr/bin/iconv",
						OwnerUID:    "0",
						OwnerGUI:    "0",
						Permissions: "755",
						Checksum:    "Q1CVmFbdY+Hv6/jAHl1gec2Kbx1EY=",
					},
					{
						Path:        "/usr/bin/ldd",
						OwnerUID:    "0",
						OwnerGUI:    "0",
						Permissions: "755",
						Checksum:    "Q1yFAhGggmL7ERgbIA7KQxyTzf3ks=",
					},
					{
						Path:        "/usr/bin/getconf",
						OwnerUID:    "0",
						OwnerGUI:    "0",
						Permissions: "755",
						Checksum:    "Q1dAdYK8M/INibRQF5B3Rw7cmNDDA=",
					},
					{
						Path:        "/usr/bin/getent",
						OwnerUID:    "0",
						OwnerGUI:    "0",
						Permissions: "755",
						Checksum:    "Q1eR2Dz/WylabgbWMTkd2+hGmEya4=",
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			file, err := os.Open("test-fixtures/single")
			if err != nil {
				t.Fatal("Unable to read test_fixtures/single: ", err)
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
		expected []pkg.Package
	}{
		{
			fixture: "test-fixtures/multiple",
			expected: []pkg.Package{
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
								Path:        "/sbin/ldconfig",
								OwnerUID:    "0",
								OwnerGUI:    "0",
								Permissions: "755",
								Checksum:    "Q1Kja2+POZKxEkUOZqwSjC6kmaED4=",
							},
							{
								Path:        "/usr/bin/iconv",
								OwnerUID:    "0",
								OwnerGUI:    "0",
								Permissions: "755",
								Checksum:    "Q1CVmFbdY+Hv6/jAHl1gec2Kbx1EY=",
							},
							{
								Path:        "/usr/bin/ldd",
								OwnerUID:    "0",
								OwnerGUI:    "0",
								Permissions: "755",
								Checksum:    "Q1yFAhGggmL7ERgbIA7KQxyTzf3ks=",
							},
							{
								Path:        "/usr/bin/getconf",
								OwnerUID:    "0",
								OwnerGUI:    "0",
								Permissions: "755",
								Checksum:    "Q1dAdYK8M/INibRQF5B3Rw7cmNDDA=",
							},
							{
								Path:        "/usr/bin/getent",
								OwnerUID:    "0",
								OwnerGUI:    "0",
								Permissions: "755",
								Checksum:    "Q1eR2Dz/WylabgbWMTkd2+hGmEya4=",
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

			pkgs, err := parseApkDB(file.Name(), file)
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
