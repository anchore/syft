package pkg

import (
	"github.com/sergi/go-diff/diffmatchpatch"
	"testing"
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
