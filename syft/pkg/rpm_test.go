package pkg

import (
	"strings"
	"testing"

	"github.com/go-test/deep"
)

func TestRpmMetadata_FileOwner(t *testing.T) {
	tests := []struct {
		metadata RpmDBEntry
		expected []string
	}{
		{
			metadata: RpmDBEntry{
				Files: []RpmFileRecord{
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
			metadata: RpmDBEntry{
				Files: []RpmFileRecord{
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
