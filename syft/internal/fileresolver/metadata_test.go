package fileresolver

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/stereoscope/pkg/file"
)

func TestFileMetadataFromPath(t *testing.T) {

	tests := []struct {
		path             string
		expectedType     file.Type
		expectedMIMEType string
	}{
		{
			path:             "test-fixtures/symlinks-simple/readme",
			expectedType:     file.TypeRegular,
			expectedMIMEType: "text/plain",
		},
		{
			path:             "test-fixtures/symlinks-simple/link_to_new_readme",
			expectedType:     file.TypeSymLink,
			expectedMIMEType: "",
		},
		{
			path:             "test-fixtures/symlinks-simple/link_to_link_to_new_readme",
			expectedType:     file.TypeSymLink,
			expectedMIMEType: "",
		},
		{
			path:             "test-fixtures/symlinks-simple",
			expectedType:     file.TypeDirectory,
			expectedMIMEType: "",
		},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			info, err := os.Lstat(test.path)
			require.NoError(t, err)

			actual := NewMetadataFromPath(test.path, info)
			assert.Equal(t, test.expectedMIMEType, actual.MIMEType, "unexpected MIME type for %s", test.path)
			assert.Equal(t, test.expectedType, actual.Type, "unexpected type for %s", test.path)
		})
	}
}
