package apkdb

import (
	"strings"
	"testing"

	"github.com/go-test/deep"
	"github.com/sergi/go-diff/diffmatchpatch"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
)

func Test_PackageURL(t *testing.T) {
	tests := []struct {
		name     string
		metadata pkg.ApkMetadata
		distro   linux.Release
		expected string
	}{
		{
			name: "non-alpine distro",
			metadata: pkg.ApkMetadata{
				Package:      "p",
				Version:      "v",
				Architecture: "a",
			},
			distro: linux.Release{
				ID:        "something else",
				VersionID: "3.4.6",
			},
			expected: "pkg:apk/something%20else/p@v?arch=a&distro=something%20else-3.4.6",
		},
		{
			name: "gocase",
			metadata: pkg.ApkMetadata{
				Package:      "p",
				Version:      "v",
				Architecture: "a",
			},
			distro: linux.Release{
				ID:        "alpine",
				VersionID: "3.4.6",
			},
			expected: "pkg:apk/alpine/p@v?arch=a&distro=alpine-3.4.6",
		},
		{
			name: "missing architecture",
			metadata: pkg.ApkMetadata{
				Package: "p",
				Version: "v",
			},
			distro: linux.Release{
				ID:        "alpine",
				VersionID: "3.4.6",
			},
			expected: "pkg:apk/alpine/p@v?distro=alpine-3.4.6",
		},
		// verify #351
		{
			metadata: pkg.ApkMetadata{
				Package:      "g++",
				Version:      "v84",
				Architecture: "am86",
			},
			distro: linux.Release{
				ID:        "alpine",
				VersionID: "3.4.6",
			},
			expected: "pkg:apk/alpine/g++@v84?arch=am86&distro=alpine-3.4.6",
		},
		{
			metadata: pkg.ApkMetadata{
				Package:      "g plus plus",
				Version:      "v84",
				Architecture: "am86",
			},
			distro: linux.Release{
				ID:        "alpine",
				VersionID: "3.15.0",
			},
			expected: "pkg:apk/alpine/g%20plus%20plus@v84?arch=am86&distro=alpine-3.15.0",
		},
		{
			name: "add source information as qualifier",
			metadata: pkg.ApkMetadata{
				Package:       "p",
				Version:       "v",
				Architecture:  "a",
				OriginPackage: "origin",
			},
			distro: linux.Release{
				ID:        "alpine",
				VersionID: "3.4.6",
			},
			expected: "pkg:apk/alpine/p@v?arch=a&upstream=origin&distro=alpine-3.4.6",
		},
		{
			name: "upstream python package information as qualifier",
			metadata: pkg.ApkMetadata{
				Package:       "py3-potatoes",
				Version:       "v",
				Architecture:  "a",
				OriginPackage: "py3-potatoes",
			},
			distro: linux.Release{
				ID:        "alpine",
				VersionID: "3.4.6",
			},
			expected: "pkg:apk/alpine/py3-potatoes@v?arch=a&upstream=potatoes&distro=alpine-3.4.6",
		},
		{
			name: "python package with origin package as upstream",
			metadata: pkg.ApkMetadata{
				Package:       "py3-non-existant",
				Version:       "v",
				Architecture:  "a",
				OriginPackage: "abcdefg",
			},
			distro: linux.Release{
				ID:        "alpine",
				VersionID: "3.4.6",
			},
			expected: "pkg:apk/alpine/py3-non-existant@v?arch=a&upstream=abcdefg&distro=alpine-3.4.6",
		},
		{
			name: "postgesql-15 upstream postgresql",
			metadata: pkg.ApkMetadata{
				Package:       "postgresql-15",
				Version:       "15.0",
				Architecture:  "a",
				OriginPackage: "postgresql-15",
			},
			distro: linux.Release{
				ID:        "alpine",
				VersionID: "3.4.6",
			},
			expected: "pkg:apk/alpine/postgresql-15@15.0?arch=a&upstream=postgresql&distro=alpine-3.4.6",
		},
		{
			name: "postgesql15 upstream postgresql",
			metadata: pkg.ApkMetadata{
				Package:       "postgresql15",
				Version:       "15.0",
				Architecture:  "a",
				OriginPackage: "postgresql15",
			},
			distro: linux.Release{
				ID:        "alpine",
				VersionID: "3.4.6",
			},
			expected: "pkg:apk/alpine/postgresql15@15.0?arch=a&upstream=postgresql&distro=alpine-3.4.6",
		},
		{
			name: "go-1.19 upstream go",
			metadata: pkg.ApkMetadata{
				Package:       "go-1.19",
				Version:       "1.19",
				Architecture:  "a",
				OriginPackage: "go-1.19",
			},
			distro: linux.Release{
				ID:        "alpine",
				VersionID: "3.4.6",
			},
			expected: "pkg:apk/alpine/go-1.19@1.19?arch=a&upstream=go&distro=alpine-3.4.6",
		},
		{
			name: "go1.19 upstream go",
			metadata: pkg.ApkMetadata{
				Package:       "go1.19",
				Version:       "1.19",
				Architecture:  "a",
				OriginPackage: "go1.19",
			},
			distro: linux.Release{
				ID:        "alpine",
				VersionID: "3.4.6",
			},
			expected: "pkg:apk/alpine/go1.19@1.19?arch=a&upstream=go&distro=alpine-3.4.6",
		},
		{
			name: "abc-101.191.23456 upstream abc",
			metadata: pkg.ApkMetadata{
				Package:       "abc-101.191.23456",
				Version:       "101.191.23456",
				Architecture:  "a",
				OriginPackage: "abc-101.191.23456",
			},
			distro: linux.Release{
				ID:        "alpine",
				VersionID: "3.4.6",
			},
			expected: "pkg:apk/alpine/abc-101.191.23456@101.191.23456?arch=a&upstream=abc&distro=alpine-3.4.6",
		},
		{
			name: "abc101.191.23456 upstream abc",
			metadata: pkg.ApkMetadata{
				Package:       "abc101.191.23456",
				Version:       "101.191.23456",
				Architecture:  "a",
				OriginPackage: "abc101.191.23456",
			},
			distro: linux.Release{
				ID:        "alpine",
				VersionID: "3.4.6",
			},
			expected: "pkg:apk/alpine/abc101.191.23456@101.191.23456?arch=a&upstream=abc&distro=alpine-3.4.6",
		},
		{
			name: "abc101-12345-1045 upstream abc101-12345",
			metadata: pkg.ApkMetadata{
				Package:       "abc101-12345-1045",
				Version:       "101.191.23456",
				Architecture:  "a",
				OriginPackage: "abc101-12345-1045",
			},
			distro: linux.Release{
				ID:        "alpine",
				VersionID: "3.4.6",
			},
			expected: "pkg:apk/alpine/abc101-12345-1045@101.191.23456?arch=a&upstream=abc101-12345&distro=alpine-3.4.6",
		},
		{
			name: "abc101-a12345-1045 upstream abc101-a12345",
			metadata: pkg.ApkMetadata{
				Package:       "abc101-a12345-1045",
				Version:       "101.191.23456",
				Architecture:  "a",
				OriginPackage: "abc101-a12345-1045",
			},
			distro: linux.Release{
				ID:        "alpine",
				VersionID: "3.4.6",
			},
			expected: "pkg:apk/alpine/abc101-a12345-1045@101.191.23456?arch=a&upstream=abc101-a12345&distro=alpine-3.4.6",
		},
		{
			name: "wolfi distro",
			metadata: pkg.ApkMetadata{
				Package:      "p",
				Version:      "v",
				Architecture: "a",
			},
			distro: linux.Release{
				ID:        "wolfi",
				VersionID: "20221230",
			},
			expected: "pkg:apk/wolfi/p@v?arch=a&distro=wolfi-20221230",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := packageURL(test.metadata, &test.distro)
			if actual != test.expected {
				dmp := diffmatchpatch.New()
				diffs := dmp.DiffMain(test.expected, actual, true)
				t.Errorf("diff: %s", dmp.DiffPrettyText(diffs))
			}

			if test.expected == "" {
				return
			}

			// verify packageurl can parse
			purl, err := packageurl.FromString(actual)
			if err != nil {
				t.Errorf("cannot re-parse purl: %s", actual)
			}
			if purl.Name != test.metadata.Package {
				dmp := diffmatchpatch.New()
				diffs := dmp.DiffMain(test.metadata.Package, purl.Name, true)
				t.Errorf("invalid purl name: %s", dmp.DiffPrettyText(diffs))
			}
			if purl.Version != test.metadata.Version {
				dmp := diffmatchpatch.New()
				diffs := dmp.DiffMain(test.metadata.Version, purl.Version, true)
				t.Errorf("invalid purl version: %s", dmp.DiffPrettyText(diffs))
			}
			if purl.Qualifiers.Map()["arch"] != test.metadata.Architecture {
				dmp := diffmatchpatch.New()
				diffs := dmp.DiffMain(test.metadata.Architecture, purl.Qualifiers.Map()["arch"], true)
				t.Errorf("invalid purl architecture: %s", dmp.DiffPrettyText(diffs))
			}
		})
	}
}

func TestApkMetadata_FileOwner(t *testing.T) {
	tests := []struct {
		metadata pkg.ApkMetadata
		expected []string
	}{
		{
			metadata: pkg.ApkMetadata{
				Files: []pkg.ApkFileRecord{
					{Path: "/somewhere"},
					{Path: "/else"},
				},
			},
			expected: []string{
				"/else",
				"/somewhere",
			},
		},
		{
			metadata: pkg.ApkMetadata{
				Files: []pkg.ApkFileRecord{
					{Path: "/somewhere"},
					{Path: ""},
				},
			},
			expected: []string{
				"/somewhere",
			},
		},
	}

	for _, test := range tests {
		t.Run(strings.Join(test.expected, ","), func(t *testing.T) {
			actual := test.metadata.OwnedFiles()
			for _, d := range deep.Equal(test.expected, actual) {
				t.Errorf("diff: %+v", d)
			}
		})
	}
}
