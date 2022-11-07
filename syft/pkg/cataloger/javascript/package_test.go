package javascript

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/packageurl-go"
)

func Test_packageURL(t *testing.T) {

	tests := []struct {
		testName  string
		name      string
		version   string
		expected  string
		namespace string
	}{
		{
			testName: "no namespace",
			name:     "arborist",
			version:  "2.6.2",
			expected: "pkg:npm/arborist@2.6.2",
		},
		{
			testName:  "split by namespace",
			name:      "npmcli/arborist",
			version:   "2.6.2",
			expected:  "pkg:npm/npmcli/arborist@2.6.2",
			namespace: "npmcli",
		},
		{
			testName:  "encoding @ symobl",
			name:      "@npmcli/arborist",
			version:   "2.6.2",
			expected:  "pkg:npm/%40npmcli/arborist@2.6.2",
			namespace: "@npmcli",
		},
	}
	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			actual := packageURL(tt.name, tt.version)
			assert.Equal(t, tt.expected, actual)
			decoded, err := packageurl.FromString(actual)
			require.NoError(t, err)
			assert.Equal(t, tt.namespace, decoded.Namespace)
			if decoded.Namespace != "" {
				assert.Equal(t, tt.name, fmt.Sprintf("%s/%s", decoded.Namespace, decoded.Name))
			} else {
				assert.Equal(t, tt.name, decoded.Name)
			}
			assert.Equal(t, tt.version, decoded.Version)
		})
	}
}
