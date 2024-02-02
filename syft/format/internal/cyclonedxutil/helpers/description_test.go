package helpers

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/pkg"
)

func Test_encodeDescription(t *testing.T) {
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
				Metadata: pkg.ApkDBEntry{
					Description: "a description!",
				},
			},
			expected: "a description!",
		},
		{
			name: "from npm",
			input: pkg.Package{
				Metadata: pkg.NpmPackage{
					Description: "a description!",
				},
			},
			expected: "a description!",
		},
		{
			// note: since this is an optional field, no value is preferred over NONE or NOASSERTION
			name: "empty",
			input: pkg.Package{
				Metadata: pkg.NpmPackage{
					Homepage: "",
				},
			},
			expected: "",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, encodeDescription(test.input))
		})
	}
}
