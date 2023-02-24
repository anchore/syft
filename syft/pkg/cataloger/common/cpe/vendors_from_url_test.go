package cpe

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_candidateVendorsFromURL(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected []string
	}{
		{
			name:     "empty",
			url:      "",
			expected: []string{},
		},
		{
			name:     "no known vendors",
			url:      "https://something-unknown.com/126374623876/12345",
			expected: []string{},
		},
		{
			name:     "gnu vendor from url",
			url:      "https://www.gnu.org/software/make",
			expected: []string{"gnu"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.ElementsMatch(t, test.expected, candidateVendorsFromURL(test.url).uniqueValues(), "different vendors")
		})
	}
}
