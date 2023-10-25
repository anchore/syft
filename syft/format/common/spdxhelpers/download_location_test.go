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
		{
			name: "from npm package-lock should include resolved",
			input: pkg.Package{
				Metadata: pkg.NpmPackageLockJSONMetadata{
					Resolved: "http://package-lock.test",
				},
			},
			expected: "http://package-lock.test",
		},
		{
			name: "from npm package-lock empty should be NONE",
			input: pkg.Package{
				Metadata: pkg.NpmPackageLockJSONMetadata{
					Resolved: "",
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
