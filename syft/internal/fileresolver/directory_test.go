//go:build !windows

package fileresolver

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func Test_RelativeRootWithSymlinkedPWD_DoesNotIndexSiblings(t *testing.T) {
	// fixture: <tmp>/fixture/physical/{proj,other}/pkg.lock and <tmp>/fixture/link -> physical (relative link)
	tmp, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)

	physical := filepath.Join(tmp, "fixture", "physical")
	for _, dir := range []string{"proj", "other"} {
		require.NoError(t, os.MkdirAll(filepath.Join(physical, dir), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(physical, dir, "pkg.lock"), []byte(dir), 0o644))
	}
	logicalCWD := filepath.Join(tmp, "fixture", "link")
	require.NoError(t, os.Symlink("physical", logicalCWD))

	// t.Chdir also sets PWD to the given (logical) path, like a shell that cd'd through the symlink
	t.Chdir(logicalCWD)

	tests := []struct {
		name string
		root string
	}{
		{name: "bare relative", root: "proj"},
		{name: "dot relative", root: "./proj"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver, err := NewFromDirectory(tt.root, "")
			require.NoError(t, err)

			var paths []string
			for loc := range resolver.AllLocations(context.Background()) {
				paths = append(paths, loc.RealPath)
			}

			for _, p := range paths {
				assert.NotContains(t, p, "/other", "sibling directory must not be indexed")
			}
			assert.Contains(t, paths, filepath.ToSlash(filepath.Join(physical, "proj", "pkg.lock")))
		})
	}
}
