package spdxhelpers

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/pkg"
)

func Test_DownloadLocation(t *testing.T) {
	tests := []struct {
		name     string
		input    pkg.Package
		expected string
	}{
		{
			name:     "no metadata",
			input:    pkg.Package{},
			expected: NOASSERTION,
		},
		{
			name: "from apk",
			input: pkg.Package{
				Metadata: pkg.ApkMetadata{
					URL: "http://a-place.gov",
				},
			},
			expected: "http://a-place.gov",
		},
		{
			name: "from npm",
			input: pkg.Package{
				Metadata: pkg.NpmPackageJSONMetadata{
					URL: "http://a-place.gov",
				},
			},
			expected: "http://a-place.gov",
		},
		{
			name: "empty",
			input: pkg.Package{
				Metadata: pkg.NpmPackageJSONMetadata{
					URL: "",
				},
			},
			expected: NONE,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, DownloadLocation(test.input))
		})
	}
}
