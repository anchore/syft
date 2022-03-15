package pkg

import (
	"strings"
	"testing"

	"github.com/go-test/deep"

	"github.com/anchore/syft/syft/linux"
	"github.com/sergi/go-diff/diffmatchpatch"
)

func TestDpkgMetadata_pURL(t *testing.T) {
	tests := []struct {
		name     string
		distro   *linux.Release
		metadata DpkgMetadata
		expected string
	}{
		{
			name: "go case",
			distro: &linux.Release{
				ID:        "debian",
				VersionID: "11",
			},
			metadata: DpkgMetadata{
				Package: "p",
				Version: "v",
			},
			expected: "pkg:deb/debian/p@v?distro=debian-11",
		},
		{
			name: "with arch info",
			distro: &linux.Release{
				ID:        "ubuntu",
				VersionID: "16.04",
			},
			metadata: DpkgMetadata{
				Package:      "p",
				Version:      "v",
				Architecture: "a",
			},
			expected: "pkg:deb/ubuntu/p@v?arch=a&distro=ubuntu-16.04",
		},
		{
			name: "missing distro",
			metadata: DpkgMetadata{
				Package: "p",
				Version: "v",
			},
			expected: "pkg:deb/p@v",
		},
		{
			name: "with upstream qualifier with source pkg name info",
			distro: &linux.Release{
				ID:        "debian",
				VersionID: "11",
			},
			metadata: DpkgMetadata{
				Package: "p",
				Source:  "s",
				Version: "v",
			},
			expected: "pkg:deb/debian/p@v?upstream=s&distro=debian-11",
		},
		{
			name: "with upstream qualifier with source pkg name and version info",
			distro: &linux.Release{
				ID:        "debian",
				VersionID: "11",
			},
			metadata: DpkgMetadata{
				Package:       "p",
				Source:        "s",
				Version:       "v",
				SourceVersion: "2.3",
			},
			expected: "pkg:deb/debian/p@v?upstream=s%402.3&distro=debian-11",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := test.metadata.PackageURL(test.distro)
			if actual != test.expected {
				dmp := diffmatchpatch.New()
				diffs := dmp.DiffMain(test.expected, actual, true)
				t.Errorf("diff: %s", dmp.DiffPrettyText(diffs))
			}
		})
	}
}

func TestDpkgMetadata_FileOwner(t *testing.T) {
	tests := []struct {
		metadata DpkgMetadata
		expected []string
	}{
		{
			metadata: DpkgMetadata{
				Files: []DpkgFileRecord{
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
			metadata: DpkgMetadata{
				Files: []DpkgFileRecord{
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
