package file

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHandleCompoundArchiveAliases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "tgz to tar.gz",
			input:    "/path/to/archive.tgz",
			expected: "/path/to/archive.tar.gz",
		},
		{
			name:     "tbz2 to tar.bz2",
			input:    "/path/to/archive.tbz2",
			expected: "/path/to/archive.tar.bz2",
		},
		{
			name:     "txz to tar.xz",
			input:    "/path/to/archive.txz",
			expected: "/path/to/archive.tar.xz",
		},
		{
			name:     "tlz to tar.lz",
			input:    "/path/to/archive.tlz",
			expected: "/path/to/archive.tar.lz",
		},
		{
			name:     "tzst to tar.zst",
			input:    "/path/to/archive.tzst",
			expected: "/path/to/archive.tar.zst",
		},
		{
			name:     "standard tar.gz unchanged",
			input:    "/path/to/archive.tar.gz",
			expected: "/path/to/archive.tar.gz",
		},
		{
			name:     "zip unchanged",
			input:    "/path/to/archive.zip",
			expected: "/path/to/archive.zip",
		},
		{
			name:     "no extension unchanged",
			input:    "/path/to/archive",
			expected: "/path/to/archive",
		},
		{
			name:     "case sensitive - TGZ not matched",
			input:    "/path/to/archive.TGZ",
			expected: "/path/to/archive.TGZ",
		},
		{
			name:     "just filename with tgz",
			input:    "archive.tgz",
			expected: "archive.tar.gz",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := handleCompoundArchiveAliases(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
