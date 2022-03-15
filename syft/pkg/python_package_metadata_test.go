package pkg

import (
	"github.com/anchore/syft/syft/linux"
	"github.com/sergi/go-diff/diffmatchpatch"
	"strings"
	"testing"

	"github.com/go-test/deep"
)

func TestPythonPackageMetadata_pURL(t *testing.T) {
	tests := []struct {
		name     string
		distro   *linux.Release
		metadata PythonPackageMetadata
		expected string
	}{
		{
			name: "with vcs info",
			metadata: PythonPackageMetadata{
				Name:    "name",
				Version: "v0.1.0",
				DirectURLOrigin: &PythonDirectURLOriginInfo{
					VCS:      "git",
					URL:      "https://github.com/test/test.git",
					CommitID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				},
			},
			expected: "pkg:pypi/name@v0.1.0?vcs_url=git+https://github.com/test/test.git%40aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		{
			name: "should not respond to release info",
			distro: &linux.Release{
				ID:        "rhel",
				VersionID: "8.4",
			},
			metadata: PythonPackageMetadata{
				Name:    "name",
				Version: "v0.1.0",
			},
			expected: "pkg:pypi/name@v0.1.0",
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

func TestPythonMetadata_FileOwner(t *testing.T) {
	tests := []struct {
		metadata PythonPackageMetadata
		expected []string
	}{
		{
			metadata: PythonPackageMetadata{
				Files: []PythonFileRecord{
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
			metadata: PythonPackageMetadata{
				Files: []PythonFileRecord{
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
