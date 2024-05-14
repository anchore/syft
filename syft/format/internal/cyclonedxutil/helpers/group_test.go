package helpers

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
				Metadata: pkg.NpmPackage{},
			},
			expected: "",
		},
		{
			name: "metadata is Java but pom properties is empty",
			input: pkg.Package{
				Metadata: pkg.JavaArchive{},
			},
			expected: "",
		},
		{
			name: "metadata is Java and contains pomProperties",
			input: pkg.Package{
				Metadata: pkg.JavaArchive{
					PomProperties: &pkg.JavaPomProperties{
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
