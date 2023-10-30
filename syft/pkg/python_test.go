package pkg

import (
	"strings"
	"testing"

	"github.com/go-test/deep"
)

func TestPythonMetadata_FileOwner(t *testing.T) {
	tests := []struct {
		metadata PythonPackage
		expected []string
	}{
		{
			metadata: PythonPackage{
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
			metadata: PythonPackage{
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
