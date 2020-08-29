package pkg

import (
	"github.com/sergi/go-diff/diffmatchpatch"
	"testing"
)

func TestJavaMetadata_pURL(t *testing.T) {
	tests := []struct {
		metadata JavaMetadata
		expected string
	}{
		{
			metadata: JavaMetadata{
				PomProperties: &PomProperties{
					Path:       "p",
					Name:       "n",
					GroupID:    "g.id",
					ArtifactID: "a",
					Version:    "v",
				},
			},
			expected: "pkg:maven/g.id/a@v",
		},
		{
			metadata: JavaMetadata{},
			expected: "",
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
