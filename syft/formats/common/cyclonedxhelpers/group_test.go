package cyclonedxhelpers

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/pkg"
)

func Test_encodeGroup(t *testing.T) {
	tests := []struct {
		name     string
		input    pkg.Package
		expected string
	}{
		{
			name:     "no metadata",
			input:    pkg.Package{},
			expected: "",
		},
		{
			name: "metadata is not Java",
			input: pkg.Package{
				Metadata: pkg.NpmPackageJSONMetadata{},
			},
			expected: "",
		},
		{
			name: "metadata is Java but pom properties is empty",
			input: pkg.Package{
				Metadata: pkg.JavaMetadata{},
			},
			expected: "",
		},
		{
			name: "metadata is Java and contains pomProperties",
			input: pkg.Package{
				Metadata: pkg.JavaMetadata{
					PomProperties: &pkg.PomProperties{
						GroupID: "test",
					},
				},
			},
			expected: "test",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, encodeGroup(test.input))
		})
	}
}
