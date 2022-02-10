package pkg

import (
	"github.com/anchore/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestNpmPackageJSONMetadata_PackageURL(t *testing.T) {

	tests := []struct {
		name     string
		metadata NpmPackageJSONMetadata
		expected string
	}{
		{
			name: "no namespace",
			metadata: NpmPackageJSONMetadata{
				Name:    "arborist",
				Version: "2.6.2",
			},
			expected: "pkg:npm/arborist@2.6.2",
		},
		{
			name: "split by namespace",
			metadata: NpmPackageJSONMetadata{
				Name:    "@npmcli/arborist",
				Version: "2.6.2",
			},
			expected: "pkg:npm/@npmcli/arborist@2.6.2",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := tt.metadata.PackageURL(nil)
			assert.Equal(t, tt.expected, actual)
			_, err := packageurl.FromString(actual)
			require.NoError(t, err)
		})
	}
}
