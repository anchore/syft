package julia

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestJuliaPackageURL(t *testing.T) {
	tests := []struct {
		name     string
		pkgName  string
		version  string
		uuid     string
		expected string
	}{
		{
			name:     "package with UUID",
			pkgName:  "Example",
			version:  "1.2.3",
			uuid:     "7876af07-990d-54b4-ab0e-23690620f79a",
			expected: "pkg:julia/Example@1.2.3?uuid=7876af07-990d-54b4-ab0e-23690620f79a",
		},
		{
			name:     "package without UUID",
			pkgName:  "Test",
			version:  "1.0.0",
			uuid:     "",
			expected: "pkg:julia/Test@1.0.0",
		},
		{
			name:     "package with special characters in name",
			pkgName:  "JSON3",
			version:  "0.21.4",
			uuid:     "682c06a0-de6a-54ab-a142-c8b1cf79cde6",
			expected: "pkg:julia/JSON3@0.21.4?uuid=682c06a0-de6a-54ab-a142-c8b1cf79cde6",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := juliaPackageURL(tt.pkgName, tt.version, tt.uuid)
			assert.Equal(t, tt.expected, result)
		})
	}
}
