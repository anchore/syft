package golang

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindAllLicenseCandidatesUpwards(t *testing.T) {
	tests := []struct {
		name          string
		setupFS       func(afero.Fs)
		startDir      string
		stopAt        string
		expectedFiles []string
		expectedError bool
		description   string
	}{
		{
			name:     "normal traversal up to root",
			startDir: "/project/subdir/deeper",
			stopAt:   "/project",
			setupFS: func(fs afero.Fs) {
				fs.MkdirAll("/project/subdir/deeper", 0755)
				afero.WriteFile(fs, "/project/LICENSE", []byte("MIT"), 0644)
				afero.WriteFile(fs, "/project/foobar", []byte("MIT"), 0644)
				afero.WriteFile(fs, "/project/subdir/LICENSE.txt", []byte("Apache"), 0644)
				afero.WriteFile(fs, "/project/subdir/deeper/COPYING", []byte("GPL"), 0644)
			},
			expectedFiles: []string{
				"/project/subdir/deeper/COPYING",
				"/project/subdir/LICENSE.txt",
				"/project/LICENSE",
			},
			description: "Should find all license files traversing upward",
		},
		{
			name:     "stops at boundary directory",
			startDir: "/project/subdir/deeper",
			stopAt:   "/project/subdir",
			setupFS: func(fs afero.Fs) {
				fs.MkdirAll("/project/subdir/deeper", 0755)
				afero.WriteFile(fs, "/project/LICENSE", []byte("MIT"), 0644)
				afero.WriteFile(fs, "/project/subdir/LICENSE.txt", []byte("Apache"), 0644)
				afero.WriteFile(fs, "/project/subdir/deeper/COPYING", []byte("GPL"), 0644)
			},
			expectedFiles: []string{
				"/project/subdir/deeper/COPYING",
				"/project/subdir/LICENSE.txt",
			},
			description: "Should stop at stopAt boundary and not find LICENSE in /project",
		},
		{
			name:     "handles non-existent directory",
			startDir: "/nonexistent",
			stopAt:   "/",
			setupFS: func(fs afero.Fs) {
				// Don't create the directory
			},
			expectedError: true,
			description:   "Should return error for non-existent directory",
		},
		{
			name:     "handles empty directory tree",
			startDir: "/empty/dir/tree",
			stopAt:   "/empty",
			setupFS: func(fs afero.Fs) {
				fs.MkdirAll("/empty/dir/tree", 0755)
				// No license files
			},
			expectedFiles: nil,
			description:   "Should return nil when no license files found",
		},
		{
			name:     "handles directory at filesystem root",
			startDir: "/",
			stopAt:   "/",
			setupFS: func(fs afero.Fs) {
				afero.WriteFile(fs, "/LICENSE", []byte("MIT"), 0644)
			},
			expectedFiles: []string{"/LICENSE"},
			description:   "Should handle traversal starting at root",
		},
		{
			name:     "ignores directories with license-like names",
			startDir: "/project/subdir",
			stopAt:   "/project",
			setupFS: func(fs afero.Fs) {
				fs.MkdirAll("/project/subdir", 0755)
				fs.MkdirAll("/project/LICENSE_DIR", 0755) // Directory, should be ignored
				afero.WriteFile(fs, "/project/LICENSE", []byte("MIT"), 0644)
			},
			expectedFiles: []string{"/project/LICENSE"},
			description:   "Should ignore directories even if they match license pattern",
		},
		{
			name:     "startDir equals stopAt",
			startDir: "/project",
			stopAt:   "/project",
			setupFS: func(fs afero.Fs) {
				fs.MkdirAll("/project", 0755)
				afero.WriteFile(fs, "/project/LICENSE", []byte("MIT"), 0644)
			},
			expectedFiles: []string{"/project/LICENSE"},
			description:   "Should handle case where start equals stop directory",
		},
		{
			name:     "startDir is parent of stopAt (returns empty)",
			startDir: "/",
			stopAt:   "/project",
			setupFS: func(fs afero.Fs) {
				fs.MkdirAll("/project", 0755)
				afero.WriteFile(fs, "/LICENSE", []byte("MIT"), 0644)
			},
			expectedFiles: []string{},
			description:   "Should return empty when startDir is above stopAt",
		},
		{
			name:     "very deep nesting",
			startDir: "/a/b/c/d/e/f/g/h/i/j",
			stopAt:   "/a",
			setupFS: func(fs afero.Fs) {
				fs.MkdirAll("/a/b/c/d/e/f/g/h/i/j", 0755)
				afero.WriteFile(fs, "/a/LICENSE", []byte("MIT"), 0644)
				afero.WriteFile(fs, "/a/b/c/d/e/NOTICE", []byte("Notice"), 0644)
			},
			expectedFiles: []string{
				"/a/b/c/d/e/NOTICE",
				"/a/LICENSE",
			},
			description: "Should handle deep directory nesting without stack overflow",
		},
		{
			name:     "relative dir path rejected",
			startDir: "project/subdir",
			stopAt:   "/project",
			setupFS: func(fs afero.Fs) {
				fs.MkdirAll("/project/subdir", 0755)
			},
			expectedError: true,
			description:   "Should reject relative dir path",
		},
		{
			name:     "relative stopAt path rejected",
			startDir: "/project/subdir",
			stopAt:   "project",
			setupFS: func(fs afero.Fs) {
				fs.MkdirAll("/project/subdir", 0755)
			},
			expectedError: true,
			description:   "Should reject relative stopAt path",
		},
		{
			name:     "stopAt is descendant of startDir",
			startDir: "/project",
			stopAt:   "/project/subdir/deeper",
			setupFS: func(fs afero.Fs) {
				fs.MkdirAll("/project/subdir/deeper", 0755)
				afero.WriteFile(fs, "/project/LICENSE", []byte("MIT"), 0644)
			},
			expectedFiles: []string{},
			description:   "Should return empty when stopAt is below startDir",
		},
		{
			name:     "disjoint paths",
			startDir: "/foo/bar",
			stopAt:   "/baz/qux",
			setupFS: func(fs afero.Fs) {
				fs.MkdirAll("/foo/bar", 0755)
				fs.MkdirAll("/baz/qux", 0755)
				afero.WriteFile(fs, "/foo/bar/LICENSE", []byte("MIT"), 0644)
				afero.WriteFile(fs, "/LICENSE", []byte("Root"), 0644)
			},
			expectedFiles: []string{},
			description:   "Should return empty for completely disjoint paths",
		},
		{
			name:     "empty stopAt rejected",
			startDir: "/project/deep/path",
			stopAt:   "",
			setupFS: func(fs afero.Fs) {
				fs.MkdirAll("/project/deep/path", 0755)
			},
			expectedError: true,
			description:   "Should reject empty stopAt string",
		},
		{
			name:     "empty startDir rejected",
			startDir: "",
			stopAt:   "/project",
			setupFS: func(fs afero.Fs) {
				fs.MkdirAll("/project", 0755)
			},
			expectedError: true,
			description:   "Should reject empty startDir string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create in-memory filesystem
			fs := afero.NewMemMapFs()
			tt.setupFS(fs)

			// Run the function
			result, err := findAllLicenseCandidatesUpwards(tt.startDir, tt.stopAt, fs)

			// Check error expectation
			if tt.expectedError {
				assert.Error(t, err, tt.description)
				return
			}

			require.NoError(t, err, tt.description)
			assert.Equal(t, tt.expectedFiles, result, tt.description)
		})
	}
}
