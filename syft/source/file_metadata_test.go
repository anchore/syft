//go:build !windows
// +build !windows

package source

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_fileMetadataFromPath(t *testing.T) {

	tests := []struct {
		path             string
		withMIMEType     bool
		expectedType     string
		expectedMIMEType string
	}{
		{
			path:             "test-fixtures/symlinks-simple/readme",
			withMIMEType:     true,
			expectedType:     "RegularFile",
			expectedMIMEType: "text/plain",
		},
		{
			path:             "test-fixtures/symlinks-simple/link_to_new_readme",
			withMIMEType:     true,
			expectedType:     "SymbolicLink",
			expectedMIMEType: "text/plain",
		},
		{
			path:             "test-fixtures/symlinks-simple/readme",
			withMIMEType:     false,
			expectedType:     "RegularFile",
			expectedMIMEType: "",
		},
		{
			path:             "test-fixtures/symlinks-simple/link_to_new_readme",
			withMIMEType:     false,
			expectedType:     "SymbolicLink",
			expectedMIMEType: "",
		},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			info, err := os.Lstat(test.path)
			require.NoError(t, err)

			actual := fileMetadataFromPath(test.path, info, test.withMIMEType)
			assert.Equal(t, test.expectedMIMEType, actual.MIMEType)
			assert.Equal(t, test.expectedType, string(actual.Type))
		})
	}
}
