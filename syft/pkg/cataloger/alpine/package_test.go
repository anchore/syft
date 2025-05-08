package alpine

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
		metadata parsedData
		distro   linux.Release
		expected string
	}{
		{
			name: "non-alpine distro",
			metadata: parsedData{
				License: "",
				ApkDBEntry: pkg.ApkDBEntry{
					Package:      "p",
					Version:      "v",
					Architecture: "a",
				},
			},
			distro: linux.Release{
				ID:        "something else",
				VersionID: "3.4.6",
			},
			expected: "pkg:apk/something%20else/p@v?arch=a&distro=something%20else-3.4.6",
		},
		{
			name: "gocase",
			metadata: parsedData{
				License: "",
				ApkDBEntry: pkg.ApkDBEntry{
					Package:      "p",
					Version:      "v",
					Architecture: "a",
				},
			},
			distro: linux.Release{
				ID:        "alpine",
				VersionID: "3.4.6",
			},
			expected: "pkg:apk/alpine/p@v?arch=a&distro=alpine-3.4.6",
		},
		{
			name: "missing architecture",
			metadata: parsedData{
				License: "",
				ApkDBEntry: pkg.ApkDBEntry{
					Package: "p",
					Version: "v",
				},
			},
			distro: linux.Release{
				ID:        "alpine",
				VersionID: "3.4.6",
			},
			expected: "pkg:apk/alpine/p@v?distro=alpine-3.4.6",
		},
		// verify #351
		{
			metadata: parsedData{
				License: "",
				ApkDBEntry: pkg.ApkDBEntry{
					Package:      "g++",
					Version:      "v84",
					Architecture: "am86",
				},
			},
			distro: linux.Release{
				ID:        "alpine",
				VersionID: "3.4.6",
			},
			expected: "pkg:apk/alpine/g%2B%2B@v84?arch=am86&distro=alpine-3.4.6",
		},
		{
			metadata: parsedData{
				License: "",
				ApkDBEntry: pkg.ApkDBEntry{
					Package:      "g plus plus",
					Version:      "v84",
					Architecture: "am86",
				},
			},
			distro: linux.Release{
				ID:        "alpine",
				VersionID: "3.15.0",
			},
			expected: "pkg:apk/alpine/g%20plus%20plus@v84?arch=am86&distro=alpine-3.15.0",
		},
		{
			name: "add source information as qualifier",
			metadata: parsedData{
				License: "",
				ApkDBEntry: pkg.ApkDBEntry{
					Package:       "p",
					Version:       "v",
					Architecture:  "a",
					OriginPackage: "origin",
				},
			},
			distro: linux.Release{
				ID:        "alpine",
				VersionID: "3.4.6",
			},
			expected: "pkg:apk/alpine/p@v?arch=a&distro=alpine-3.4.6&upstream=origin",
		},
		{
			name: "wolfi distro",
			metadata: parsedData{
				License: "",
				ApkDBEntry: pkg.ApkDBEntry{
					Package:      "p",
					Version:      "v",
					Architecture: "a",
				},
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
			actual := packageURL(test.metadata.ApkDBEntry, &test.distro)
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
		metadata pkg.ApkDBEntry
		expected []string
	}{
		{
			metadata: pkg.ApkDBEntry{
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
			metadata: pkg.ApkDBEntry{
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
