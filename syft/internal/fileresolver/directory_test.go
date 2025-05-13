//go:build !windows
// +build !windows

package fileresolver

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_isUnallowableFileType(t *testing.T) {
	tests := []struct {
		name     string
		info     os.FileInfo
		expected error
	}{
		{
			name: "regular file",
			info: testFileInfo{
				mode: 0,
			},
		},
		{
			name: "dir",
			info: testFileInfo{
				mode: os.ModeDir,
			},
		},
		{
			name: "symlink",
			info: testFileInfo{
				mode: os.ModeSymlink,
			},
		},
		{
			name: "socket",
			info: testFileInfo{
				mode: os.ModeSocket,
			},
			expected: ErrSkipPath,
		},
		{
			name: "named pipe",
			info: testFileInfo{
				mode: os.ModeNamedPipe,
			},
			expected: ErrSkipPath,
		},
		{
			name: "char device",
			info: testFileInfo{
				mode: os.ModeCharDevice,
			},
			expected: ErrSkipPath,
		},
		{
			name: "block device",
			info: testFileInfo{
				mode: os.ModeDevice,
			},
			expected: ErrSkipPath,
		},
		{
			name: "irregular",
			info: testFileInfo{
				mode: os.ModeIrregular,
			},
			expected: ErrSkipPath,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, disallowByFileType("", "dont/care", test.info, nil))
		})
	}
}
