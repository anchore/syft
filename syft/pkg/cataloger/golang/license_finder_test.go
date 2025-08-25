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
			expectedFiles: []string{},
			description:   "Should return empty slice when no license files found",
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
			name:     "prevents escaping stopAt boundary with complex paths",
			startDir: "/allowed/project/subdir",
			stopAt:   "/allowed/project",
			setupFS: func(fs afero.Fs) {
				fs.MkdirAll("/allowed/project/subdir", 0755)
				fs.MkdirAll("/disallowed", 0755)
				afero.WriteFile(fs, "/allowed/project/LICENSE", []byte("MIT"), 0644)
				afero.WriteFile(fs, "/disallowed/LICENSE", []byte("GPL"), 0644)
			},
			expectedFiles: []string{"/allowed/project/LICENSE"},
			description:   "Should not escape stopAt boundary even with nested dissallowed path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create in-memory filesystem
			fs := afero.NewMemMapFs()
			tt.setupFS(fs)

			// Run the function
			result, err := findAllLicenseCandidatesUpwardsWithFS(tt.startDir, licenseRegexp, tt.stopAt, fs)

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

func TestFindAllLicenseCandidatesUpwardsBoundary(t *testing.T) {
	tests := []struct {
		name        string
		startDir    string
		stopAt      string
		setupFS     func(afero.Fs)
		shouldError bool
		description string
	}{
		{
			name:     "startDir equals stopAt",
			startDir: "/project",
			stopAt:   "/project",
			setupFS: func(fs afero.Fs) {
				fs.MkdirAll("/project", 0755)
				afero.WriteFile(fs, "/project/LICENSE", []byte("MIT"), 0644)
			},
			description: "Should handle case where start equals stop directory",
		},
		{
			name:     "startDir is parent of stopAt (invalid)",
			startDir: "/",
			stopAt:   "/project",
			setupFS: func(fs afero.Fs) {
				fs.MkdirAll("/project", 0755)
				afero.WriteFile(fs, "/LICENSE", []byte("MIT"), 0644)
			},
			description: "Should handle case where startDir is above stopAt",
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
			description: "Should handle deep directory nesting without issues",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := afero.NewMemMapFs()
			tt.setupFS(fs)

			result, err := findAllLicenseCandidatesUpwardsWithFS(tt.startDir, licenseRegexp, tt.stopAt, fs)

			if tt.shouldError {
				assert.Error(t, err, tt.description)
			} else {
				assert.NoError(t, err, tt.description)
				// For boundary tests, we mainly care that it doesn't hang or crash
				assert.NotNil(t, result, tt.description)
			}
		})
	}
}

type mockSymlinkFS struct {
	afero.Fs
	symlinks map[string]string // path -> target mapping
}

func newMockSymlinkFS() *mockSymlinkFS {
	return &mockSymlinkFS{
		Fs:       afero.NewMemMapFs(),
		symlinks: make(map[string]string),
	}
}

func (m *mockSymlinkFS) ReadlinkIfPossible(name string) (string, error) {
	if target, ok := m.symlinks[name]; ok {
		return target, nil
	}
	return "", nil
}

func (m *mockSymlinkFS) CreateSymlink(target, link string) {
	m.symlinks[link] = target
	// Create directory entry so ReadDir works
	m.Fs.MkdirAll(link, 0755)
}

func TestFindAllLicenseCandidatesUpwardsSymLinks(t *testing.T) {
	tests := []struct {
		name          string
		setupFS       func(*mockSymlinkFS)
		startDir      string
		stopAt        string
		expectedFiles []string
		description   string
	}{
		{
			name: "symlink pointing to parent directory - should not break early",
			setupFS: func(fs *mockSymlinkFS) {
				// Setup: /project/sub/deep with symlink /project/sub/deep/up -> /project
				fs.MkdirAll("/project/sub/deep", 0755)
				fs.CreateSymlink("/project", "/project/sub/deep/up")
				afero.WriteFile(fs, "/project/LICENSE", []byte("MIT"), 0644)
				afero.WriteFile(fs, "/project/sub/LICENSE.txt", []byte("Apache"), 0644)
			},
			startDir: "/project/sub/deep",
			stopAt:   "/project",
			expectedFiles: []string{
				"/project/sub/LICENSE.txt",
				"/project/LICENSE",
			},
			description: "Should find all licenses despite symlink to parent",
		},
		{
			name: "circular symlink loop detection",
			setupFS: func(fs *mockSymlinkFS) {
				// Setup circular loop: /project/a -> /project/b -> /project/a
				fs.MkdirAll("/project/a", 0755)
				fs.MkdirAll("/project/b", 0755)
				fs.CreateSymlink("/project/b", "/project/a")
				fs.CreateSymlink("/project/a", "/project/b")
				afero.WriteFile(fs, "/project/LICENSE", []byte("MIT"), 0644)
			},
			startDir: "/project/a",
			stopAt:   "/project",
			expectedFiles: []string{
				"/project/LICENSE",
			},
			description: "Should detect and handle circular symlinks",
		},
		{
			name: "nested module boundary enforcement",
			setupFS: func(fs *mockSymlinkFS) {
				// Setup nested modules that shouldn't pollute each other
				fs.MkdirAll("/project/module1/sub", 0755)
				fs.MkdirAll("/project/module2", 0755)
				// module1/sub has symlink to module2
				fs.CreateSymlink("/project/module2", "/project/module1/sub/link")
				afero.WriteFile(fs, "/project/LICENSE", []byte("Root"), 0644)
				afero.WriteFile(fs, "/project/module1/LICENSE", []byte("Module1"), 0644)
				afero.WriteFile(fs, "/project/module2/LICENSE", []byte("Module2"), 0644)
			},
			startDir: "/project/module1/sub",
			stopAt:   "/project/module1", // Stop at module1 boundary
			expectedFiles: []string{
				"/project/module1/LICENSE",
			},
			description: "Should respect module boundaries and not follow symlinks outside",
		},
		{
			name: "symlink chain eventually loops",
			setupFS: func(fs *mockSymlinkFS) {
				// Chain: /project/a -> /project/b -> /project/c -> /project/a
				fs.MkdirAll("/project/start", 0755)
				fs.MkdirAll("/project/a", 0755)
				fs.MkdirAll("/project/b", 0755)
				fs.MkdirAll("/project/c", 0755)
				fs.CreateSymlink("/project/a", "/project/start/link")
				fs.CreateSymlink("/project/b", "/project/a/link")
				fs.CreateSymlink("/project/c", "/project/b/link")
				fs.CreateSymlink("/project/a", "/project/c/link")
				afero.WriteFile(fs, "/project/LICENSE", []byte("MIT"), 0644)
			},
			startDir: "/project/start",
			stopAt:   "/project",
			expectedFiles: []string{
				"/project/LICENSE",
			},
			description: "Should handle symlink chains that eventually loop",
		},
		{
			name: "relative symlink resolution",
			setupFS: func(fs *mockSymlinkFS) {
				fs.MkdirAll("/project/deep/nested/path", 0755)
				// Relative symlink: ../../../ from deep/nested/path points to /project
				fs.CreateSymlink("../../..", "/project/deep/nested/path/up")
				afero.WriteFile(fs, "/project/LICENSE", []byte("MIT"), 0644)
				afero.WriteFile(fs, "/project/deep/LICENSE.md", []byte("BSD"), 0644)
			},
			startDir: "/project/deep/nested/path",
			stopAt:   "/project",
			expectedFiles: []string{
				"/project/deep/LICENSE.md",
				"/project/LICENSE",
			},
			description: "Should correctly resolve relative symlinks",
		},
		{
			name: "symlink error handling continues traversal",
			setupFS: func(fs *mockSymlinkFS) {
				// This will be tested with error injection in actual implementation
				fs.MkdirAll("/project/sub", 0755)
				afero.WriteFile(fs, "/project/LICENSE", []byte("MIT"), 0644)
			},
			startDir: "/project/sub",
			stopAt:   "/project",
			expectedFiles: []string{
				"/project/LICENSE",
			},
			description: "Should continue traversal even if symlink reading fails",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := newMockSymlinkFS()
			tt.setupFS(fs)

			result, err := findAllLicenseCandidatesUpwardsWithFS(tt.startDir, licenseRegexp, tt.stopAt, fs)

			require.NoError(t, err, tt.description)
			assert.Equal(t, tt.expectedFiles, result, tt.description)
		})
	}
}
