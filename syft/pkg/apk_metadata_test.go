package pkg

import (
	"strings"
	"testing"

	"github.com/go-test/deep"
	"github.com/sergi/go-diff/diffmatchpatch"
)

func TestApkMetadata_pURL(t *testing.T) {
	tests := []struct {
		metadata ApkMetadata
		expected string
	}{
		{
			metadata: ApkMetadata{
				Package:      "p",
				Version:      "v",
				Architecture: "a",
			},
			expected: "pkg:alpine/p@v?arch=a",
		},
	}

	for _, test := range tests {
		t.Run(test.expected, func(t *testing.T) {
			actual := test.metadata.PackageURL()
			if actual != test.expected {
				dmp := diffmatchpatch.New()
				diffs := dmp.DiffMain(test.expected, actual, true)
				t.Errorf("diff: %s", dmp.DiffPrettyText(diffs))
			}
		})
	}
}

func TestApkMetadata_fileOwner(t *testing.T) {
	tests := []struct {
		metadata ApkMetadata
		expected []string
	}{
		{
			metadata: ApkMetadata{
				Files: []ApkFileRecord{
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
			metadata: ApkMetadata{
				Files: []ApkFileRecord{
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
			var i interface{}
			i = test.metadata
			actual := i.(fileOwner).ownedFiles()
			for _, d := range deep.Equal(test.expected, actual) {
				t.Errorf("diff: %+v", d)
			}
		})
	}
}
