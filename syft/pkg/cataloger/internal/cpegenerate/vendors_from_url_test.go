package cpegenerate

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
		{
			name:     "github username as vendor",
			url:      "https://github.com/armadillo/abcxyz-12345",
			expected: []string{"armadillo"},
		},
		{
			name:     "github username with - as vendor",
			url:      "https://github.com/1234-abc-xyz/hello",
			expected: []string{"1234-abc-xyz"},
		},
		{
			name:     "gitlab username as vendor",
			url:      "https://gitlab.com/armadillo/abcxyz-12345",
			expected: []string{"armadillo"},
		},
		{
			name:     "gitlab username with - as vendor",
			url:      "https://gitlab.com/1234-abc-xyz/hello",
			expected: []string{"1234-abc-xyz"},
		},
		{
			name:     "github username as vendor from longer url",
			url:      "https://github.com/armadillo/abcxyz-12345/a/b/c/d/e/f/g",
			expected: []string{"armadillo"},
		},
		{
			name:     "github username from git://",
			url:      "git://github.com/abc/xyz.git",
			expected: []string{"abc"},
		},
		{
			name:     "github username from http://",
			url:      "http://github.com/abc/xyz.git",
			expected: []string{"abc"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.ElementsMatch(t, test.expected, candidateVendorsFromURL(test.url).uniqueValues(), "different vendors")
		})
	}
}
