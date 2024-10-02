package lua

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/packageurl-go"
)

func Test_packageURL(t *testing.T) {

	tests := []struct {
		testName string
		name     string
		version  string
		expected string
	}{
		{
			name:     "kong",
			version:  "3.7.0-0",
			expected: "pkg:luarocks/kong@3.7.0-0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			actual := packageURL(tt.name, tt.version)
			assert.Equal(t, tt.expected, actual)
			decoded, err := packageurl.FromString(actual)
			require.NoError(t, err)
			assert.Equal(t, tt.name, decoded.Name)
			assert.Equal(t, tt.version, decoded.Version)
		})
	}
}
