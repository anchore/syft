package testutil

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateSnippet(t *testing.T) {
	tests := []struct {
		name           string
		binaryContent  string
		snippetContent string
		expectError    bool
	}{
		{
			name:          "valid",
			binaryContent: "testBinary",
			snippetContent: `name: bash
offset: 992758
length: 100
snippetSha256: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
fileSha256: 88ef99f28b69a6d8113cba62011e574a5afb1e6d8e0f884699e2ced91e4d910c

### byte snippet to follow ###
hello`,
			expectError: false,
		},
		{
			name:          "invalid",
			binaryContent: "testBinary",
			snippetContent: `name: bash
offset: 992758
length: 100
snippetSha256: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
fileSha256: 011e574a8ef9584699e2ced9189f28b69a6d8113cba62e4d910cafb1e6d8e0f8

### byte snippet to follow ###
hello`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			binaryFile, _ := os.CreateTemp(t.TempDir(), "binary")
			binaryFile.WriteString(tt.binaryContent)
			binaryFile.Close()

			snippetFile, _ := os.CreateTemp(t.TempDir(), "snippet")
			snippetFile.WriteString(tt.snippetContent)
			snippetFile.Close()

			err := validateSnippet(binaryFile.Name(), snippetFile.Name())
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
