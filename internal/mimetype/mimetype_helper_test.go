package mimetype

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_IsArchive(t *testing.T) {

	tests := []struct {
		name     string
		mimeType string
		expected bool
	}{
		{
			name:     "not an archive",
			mimeType: "application/vnd.unknown",
			expected: false,
		},
		{
			name:     "archive",
			mimeType: "application/x-rar-compressed",
			expected: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, IsArchive(test.mimeType))
		})
	}
}

func Test_IsExecutable(t *testing.T) {

	tests := []struct {
		name     string
		mimeType string
		expected bool
	}{
		{
			name:     "not an executable",
			mimeType: "application/vnd.unknown",
			expected: false,
		},
		{
			name:     "executable",
			mimeType: "application/x-mach-binary",
			expected: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, IsExecutable(test.mimeType))
		})
	}
}
