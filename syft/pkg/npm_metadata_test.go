package pkg

import (
	"strings"
	"testing"

	"github.com/go-test/deep"
)

func TestNpmMetadata_fileOwner(t *testing.T) {
	tests := []struct {
		metadata NpmPackageJSONMetadata
		expected []string
	}{
		{
			metadata: NpmPackageJSONMetadata{
				Files: []string{
					"/somewhere",
					"/else",
				},
			},
			expected: []string{
				"/somewhere",
				"/else",
			},
		},
		{
			metadata: NpmPackageJSONMetadata{
				Files: []string{
					"/somewhere",
					"",
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
