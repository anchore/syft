package spdxhelpers

import (
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/stretchr/testify/assert"
)

func Test_Description(t *testing.T) {
	tests := []struct {
		name     string
		input    pkg.Package
		expected string
	}{
		{
			// note: since this is an optional field, no value is preferred over NONE or NOASSERTION
			name:     "no metadata",
			input:    pkg.Package{},
			expected: "",
		},
		{
			name: "from apk",
			input: pkg.Package{
				Metadata: pkg.ApkMetadata{
					Description: "a description!",
				},
			},
			expected: "a description!",
		},
		{
			name: "from npm",
			input: pkg.Package{
				Metadata: pkg.NpmPackageJSONMetadata{
					Description: "a description!",
				},
			},
			expected: "a description!",
		},
		{
			// note: since this is an optional field, no value is preferred over NONE or NOASSERTION
			name: "empty",
			input: pkg.Package{
				Metadata: pkg.NpmPackageJSONMetadata{
					Homepage: "",
				},
			},
			expected: "",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, Description(test.input))
		})
	}
}
