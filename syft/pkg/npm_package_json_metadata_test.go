package pkg

import (
	"fmt"
	"testing"

	"github.com/anchore/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNpmPackageJSONMetadata_PackageURL(t *testing.T) {

	tests := []struct {
		name      string
		metadata  NpmPackageJSONMetadata
		expected  string
		namespace string
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
				Name:    "npmcli/arborist",
				Version: "2.6.2",
			},
			expected:  "pkg:npm/npmcli/arborist@2.6.2",
			namespace: "npmcli",
		},
		{
			name: "encoding @ symobl",
			metadata: NpmPackageJSONMetadata{
				Name:    "@npmcli/arborist",
				Version: "2.6.2",
			},
			expected:  "pkg:npm/%40npmcli/arborist@2.6.2",
			namespace: "@npmcli",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := tt.metadata.PackageURL(nil)
			assert.Equal(t, tt.expected, actual)
			decoded, err := packageurl.FromString(actual)
			require.NoError(t, err)
			assert.Equal(t, tt.namespace, decoded.Namespace)
			if decoded.Namespace != "" {
				assert.Equal(t, tt.metadata.Name, fmt.Sprintf("%s/%s", decoded.Namespace, decoded.Name))
			} else {
				assert.Equal(t, tt.metadata.Name, decoded.Name)
			}
			assert.Equal(t, tt.metadata.Version, decoded.Version)
		})
	}
}
