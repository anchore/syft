package helpers

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/pkg"
)

func Test_encodeCPE(t *testing.T) {
	testCPE := cpe.Must("cpe:2.3:a:name:name:3.2:*:*:*:*:*:*:*", "test-source")
	testCPE2 := cpe.Must("cpe:2.3:a:name:name2:3.2:*:*:*:*:*:*:*", "test-source-2")
	tests := []struct {
		name     string
		input    pkg.Package
		expected string
	}{
		{
			// note: since this is an optional field, no value is preferred over NONE or NOASSERTION
			name: "no metadata",
			input: pkg.Package{
				CPEs: []cpe.CPE{},
			},
			expected: "",
		},
		{
			name: "single Attributes",
			input: pkg.Package{
				CPEs: []cpe.CPE{
					testCPE,
				},
			},
			expected: "cpe:2.3:a:name:name:3.2:*:*:*:*:*:*:*",
		},
		{
			name: "multiple CPEs",
			input: pkg.Package{
				CPEs: []cpe.CPE{
					testCPE2,
					testCPE,
				},
			},
			expected: "cpe:2.3:a:name:name2:3.2:*:*:*:*:*:*:*",
		},
		{
			// note: since this is an optional field, no value is preferred over NONE or NOASSERTION
			name:     "empty",
			input:    pkg.Package{},
			expected: "",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, encodeSingleCPE(test.input))
		})
	}
}
