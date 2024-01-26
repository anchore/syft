package helpers

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/pkg"
)

func Test_encodePublisher(t *testing.T) {
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
					Maintainer: "auth",
				},
			},
			expected: "auth",
		},
		{
			name: "from rpm",
			input: pkg.Package{
				Metadata: pkg.RpmDBEntry{
					Vendor: "auth",
				},
			},
			expected: "auth",
		},
		{
			name: "from dpkg",
			input: pkg.Package{
				Metadata: pkg.DpkgDBEntry{
					Maintainer: "auth",
				},
			},
			expected: "auth",
		},
		{
			// note: since this is an optional field, no value is preferred over NONE or NOASSERTION
			name: "empty",
			input: pkg.Package{
				Metadata: pkg.NpmPackage{
					Author: "",
				},
			},
			expected: "",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, encodePublisher(test.input))
		})
	}
}
