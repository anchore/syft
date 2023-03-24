package cyclonedxhelpers

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/pkg"
)

func Test_encodeAuthor(t *testing.T) {
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
			name: "from gem",
			input: pkg.Package{
				Metadata: pkg.GemMetadata{
					Authors: []string{
						"auth1",
						"auth2",
					},
				},
			},
			expected: "auth1,auth2",
		},
		{
			name: "from npm",
			input: pkg.Package{
				Metadata: pkg.NpmPackageJSONMetadata{
					Author: "auth",
				},
			},
			expected: "auth",
		},
		{
			name: "from python - just name",
			input: pkg.Package{
				Metadata: pkg.PythonPackageMetadata{
					Author: "auth",
				},
			},
			expected: "auth",
		},
		{
			name: "from python - just email",
			input: pkg.Package{
				Metadata: pkg.PythonPackageMetadata{
					AuthorEmail: "auth@auth.gov",
				},
			},
			expected: "auth@auth.gov",
		},
		{
			name: "from python - both name and email",
			input: pkg.Package{
				Metadata: pkg.PythonPackageMetadata{
					Author:      "auth",
					AuthorEmail: "auth@auth.gov",
				},
			},
			expected: "auth <auth@auth.gov>",
		},
		{
			// note: since this is an optional field, no value is preferred over NONE or NOASSERTION
			name: "empty",
			input: pkg.Package{
				Metadata: pkg.NpmPackageJSONMetadata{
					Author: "",
				},
			},
			expected: "",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, encodeAuthor(test.input))
		})
	}
}
