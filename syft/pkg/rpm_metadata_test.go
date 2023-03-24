package pkg

import (
	"strings"
	"testing"

	"github.com/go-test/deep"
)

func TestRpmMetadata_FileOwner(t *testing.T) {
	tests := []struct {
		metadata RpmMetadata
		expected []string
	}{
		{
			metadata: RpmMetadata{
				Files: []RpmdbFileRecord{
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
			metadata: RpmMetadata{
				Files: []RpmdbFileRecord{
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
