package internal

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadSnippetMetadata(t *testing.T) {
	tests := []struct {
		name           string
		content        string
		createFile     bool
		expectedError  bool
		expectedResult *SnippetMetadata
	}{
		{
			name:           "valid metadata",
			content:        "name: test\noffset: 10\nlength: 20\nsnippetSha256: abcd\nfileSha256: efgh\n### byte snippet to follow ###\n",
			expectedError:  false,
			expectedResult: &SnippetMetadata{Name: "test", Offset: 10, Length: 20, SnippetSha256: "abcd", FileSha256: "efgh"},
		},
		{
			name:          "invalid format",
			content:       "invalid content",
			expectedError: true,
		},
		{
			name:          "Empty content",
			content:       "",
			createFile:    true,
			expectedError: true,
		},
		{
			name:          "no path",
			expectedError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var path string
			if tc.content != "" || tc.createFile {
				path = createTestFile(t, tc.content)
			}

			result, err := ReadSnippetMetadata(path)
			if tc.expectedError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedResult, result)
			}
		})
	}
}

func createTestFile(t *testing.T, content string) string {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "syft-test-snippetMetadata")
	require.NoError(t, err)
	if len(content) > 0 {
		_, err = file.WriteString(content)
		require.NoError(t, err)
	}
	require.NoError(t, file.Close())
	return file.Name()
}
