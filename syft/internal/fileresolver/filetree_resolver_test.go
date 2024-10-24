//go:build !windows
// +build !windows

package fileresolver

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/file"
	"github.com/google/go-cmp/cmp"
	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

// Tests for filetree resolver when directory is used for index
func TestDirectoryResolver_FilesByPath_request_response(t *testing.T) {
	// /
	//   somewhere/
	//     outside.txt
	//   root-link -> ./
	//   path/
	//     to/
	//       abs-inside.txt -> /path/to/the/file.txt               # absolute link to somewhere inside of the root
	//       rel-inside.txt -> ./the/file.txt                      # relative link to somewhere inside of the root
	//       the/
	//		   file.txt
	//         abs-outside.txt -> /somewhere/outside.txt           # absolute link to outside of the root
	//         rel-outside -> ../../../somewhere/outside.txt       # relative link to outside of the root
	//

	testDir, err := os.Getwd()
	require.NoError(t, err)
	relative := filepath.Join("test-fixtures", "req-resp")
	absolute := filepath.Join(testDir, relative)

	absInsidePath := filepath.Join(absolute, "path", "to", "abs-inside.txt")
	absOutsidePath := filepath.Join(absolute, "path", "to", "the", "abs-outside.txt")

	relativeViaLink := filepath.Join(relative, "root-link")
	absoluteViaLink := filepath.Join(absolute, "root-link")

	relativeViaDoubleLink := filepath.Join(relative, "root-link", "root-link")
	absoluteViaDoubleLink := filepath.Join(absolute, "root-link", "root-link")

	cleanup := func() {
		_ = os.Remove(absInsidePath)
		_ = os.Remove(absOutsidePath)
	}

	// ensure the absolute symlinks are cleaned up from any previous runs
	cleanup()

	require.NoError(t, os.Symlink(filepath.Join(absolute, "path", "to", "the", "file.txt"), absInsidePath))
	require.NoError(t, os.Symlink(filepath.Join(absolute, "somewhere", "outside.txt"), absOutsidePath))

	t.Cleanup(cleanup)

	cases := []struct {
		name               string
		cwd                string
		root               string
		base               string
		input              string
		expectedRealPath   string
		expectedAccessPath string // note: if empty it will be assumed to match the expectedRealPath
	}{
		{
			name:             "relative root, relative request, direct",
			root:             relative,
			input:            "path/to/the/file.txt",
			expectedRealPath: "path/to/the/file.txt",
		},
		{
			name:             "abs root, relative request, direct",
			root:             absolute,
			input:            "path/to/the/file.txt",
			expectedRealPath: "path/to/the/file.txt",
		},
		{
			name:             "relative root, abs request, direct",
			root:             relative,
			input:            "/path/to/the/file.txt",
			expectedRealPath: "path/to/the/file.txt",
		},
		{
			name:             "abs root, abs request, direct",
			root:             absolute,
			input:            "/path/to/the/file.txt",
			expectedRealPath: "path/to/the/file.txt",
		},
		// cwd within root...
		{
			name:             "relative root, relative request, direct, cwd within root",
			cwd:              filepath.Join(relative, "path/to"),
			root:             "../../",
			input:            "path/to/the/file.txt",
			expectedRealPath: "path/to/the/file.txt",
		},
		{
			name:             "abs root, relative request, direct, cwd within root",
			cwd:              filepath.Join(relative, "path/to"),
			root:             absolute,
			input:            "path/to/the/file.txt",
			expectedRealPath: "path/to/the/file.txt",
		},
		{
			name:             "relative root, abs request, direct, cwd within root",
			cwd:              filepath.Join(relative, "path/to"),
			root:             "../../",
			input:            "/path/to/the/file.txt",
			expectedRealPath: "path/to/the/file.txt",
		},
		{
			name: "abs root, abs request, direct, cwd within root",
			cwd:  filepath.Join(relative, "path/to"),

			root:             absolute,
			input:            "/path/to/the/file.txt",
			expectedRealPath: "path/to/the/file.txt",
		},
		// cwd within symlink root...
		{
			name:  "relative root, relative request, direct, cwd within symlink root",
			cwd:   relativeViaLink,
			root:  "./",
			input: "path/to/the/file.txt",
			// note: why not expect "path/to/the/file.txt" here?
			// this is because we don't know that the path used to access this path (which is a link within
			// the root) resides within the root. Without this information it appears as if this file resides
			// outside the root.
			expectedRealPath: filepath.Join(absolute, "path/to/the/file.txt"),
			//expectedRealPath:    "path/to/the/file.txt",
			expectedAccessPath: "path/to/the/file.txt",
		},
		{
			name:             "abs root, relative request, direct, cwd within symlink root",
			cwd:              relativeViaLink,
			root:             absoluteViaLink,
			input:            "path/to/the/file.txt",
			expectedRealPath: "path/to/the/file.txt",
		},
		{
			name:  "relative root, abs request, direct, cwd within symlink root",
			cwd:   relativeViaLink,
			root:  "./",
			input: "/path/to/the/file.txt",
			// note: why not expect "path/to/the/file.txt" here?
			// this is because we don't know that the path used to access this path (which is a link within
			// the root) resides within the root. Without this information it appears as if this file resides
			// outside the root.
			expectedRealPath: filepath.Join(absolute, "path/to/the/file.txt"),
			//expectedRealPath:    "path/to/the/file.txt",
			expectedAccessPath: "path/to/the/file.txt",
		},
		{
			name:             "abs root, abs request, direct, cwd within symlink root",
			cwd:              relativeViaLink,
			root:             absoluteViaLink,
			input:            "/path/to/the/file.txt",
			expectedRealPath: "path/to/the/file.txt",
		},
		// cwd within symlink root, request nested within...
		{
			name:  "relative root, relative nested request, direct, cwd within symlink root",
			cwd:   relativeViaLink,
			root:  "./path",
			input: "to/the/file.txt",
			// note: why not expect "to/the/file.txt" here?
			// this is because we don't know that the path used to access this path (which is a link within
			// the root) resides within the root. Without this information it appears as if this file resides
			// outside the root.
			expectedRealPath: filepath.Join(absolute, "path/to/the/file.txt"),
			//expectedRealPath: "to/the/file.txt",
			expectedAccessPath: "to/the/file.txt",
		},
		{
			name:             "abs root, relative nested request, direct, cwd within symlink root",
			cwd:              relativeViaLink,
			root:             filepath.Join(absoluteViaLink, "path"),
			input:            "to/the/file.txt",
			expectedRealPath: "to/the/file.txt",
		},
		{
			name:  "relative root, abs nested request, direct, cwd within symlink root",
			cwd:   relativeViaLink,
			root:  "./path",
			input: "/to/the/file.txt",
			// note: why not expect "to/the/file.txt" here?
			// this is because we don't know that the path used to access this path (which is a link within
			// the root) resides within the root. Without this information it appears as if this file resides
			// outside the root.
			expectedRealPath: filepath.Join(absolute, "path/to/the/file.txt"),
			//expectedRealPath: "to/the/file.txt",
			expectedAccessPath: "to/the/file.txt",
		},
		{
			name:             "abs root, abs nested request, direct, cwd within symlink root",
			cwd:              relativeViaLink,
			root:             filepath.Join(absoluteViaLink, "path"),
			input:            "/to/the/file.txt",
			expectedRealPath: "to/the/file.txt",
		},
		// cwd within DOUBLE symlink root...
		{
			name:  "relative root, relative request, direct, cwd within (double) symlink root",
			cwd:   relativeViaDoubleLink,
			root:  "./",
			input: "path/to/the/file.txt",
			// note: why not expect "path/to/the/file.txt" here?
			// this is because we don't know that the path used to access this path (which is a link within
			// the root) resides within the root. Without this information it appears as if this file resides
			// outside the root.
			expectedRealPath: filepath.Join(absolute, "path/to/the/file.txt"),
			//expectedRealPath:    "path/to/the/file.txt",
			expectedAccessPath: "path/to/the/file.txt",
		},
		{
			name:             "abs root, relative request, direct, cwd within (double) symlink root",
			cwd:              relativeViaDoubleLink,
			root:             absoluteViaDoubleLink,
			input:            "path/to/the/file.txt",
			expectedRealPath: "path/to/the/file.txt",
		},
		{
			name:  "relative root, abs request, direct, cwd within (double) symlink root",
			cwd:   relativeViaDoubleLink,
			root:  "./",
			input: "/path/to/the/file.txt",
			// note: why not expect "path/to/the/file.txt" here?
			// this is because we don't know that the path used to access this path (which is a link within
			// the root) resides within the root. Without this information it appears as if this file resides
			// outside the root.
			expectedRealPath: filepath.Join(absolute, "path/to/the/file.txt"),
			//expectedRealPath:    "path/to/the/file.txt",
			expectedAccessPath: "path/to/the/file.txt",
		},
		{
			name:             "abs root, abs request, direct, cwd within (double) symlink root",
			cwd:              relativeViaDoubleLink,
			root:             absoluteViaDoubleLink,
			input:            "/path/to/the/file.txt",
			expectedRealPath: "path/to/the/file.txt",
		},
		// cwd within DOUBLE symlink root, request nested within...
		{
			name:  "relative root, relative nested request, direct, cwd within (double) symlink root",
			cwd:   relativeViaDoubleLink,
			root:  "./path",
			input: "to/the/file.txt",
			// note: why not expect "path/to/the/file.txt" here?
			// this is because we don't know that the path used to access this path (which is a link within
			// the root) resides within the root. Without this information it appears as if this file resides
			// outside the root.
			expectedRealPath: filepath.Join(absolute, "path/to/the/file.txt"),
			//expectedRealPath:    "to/the/file.txt",
			expectedAccessPath: "to/the/file.txt",
		},
		{
			name:             "abs root, relative nested request, direct, cwd within (double) symlink root",
			cwd:              relativeViaDoubleLink,
			root:             filepath.Join(absoluteViaDoubleLink, "path"),
			input:            "to/the/file.txt",
			expectedRealPath: "to/the/file.txt",
		},
		{
			name:  "relative root, abs nested request, direct, cwd within (double) symlink root",
			cwd:   relativeViaDoubleLink,
			root:  "./path",
			input: "/to/the/file.txt",
			// note: why not expect "path/to/the/file.txt" here?
			// this is because we don't know that the path used to access this path (which is a link within
			// the root) resides within the root. Without this information it appears as if this file resides
			// outside the root.
			expectedRealPath: filepath.Join(absolute, "path/to/the/file.txt"),
			//expectedRealPath:    "to/the/file.txt",
			expectedAccessPath: "to/the/file.txt",
		},
		{
			name:             "abs root, abs nested request, direct, cwd within (double) symlink root",
			cwd:              relativeViaDoubleLink,
			root:             filepath.Join(absoluteViaDoubleLink, "path"),
			input:            "/to/the/file.txt",
			expectedRealPath: "to/the/file.txt",
		},
		// cwd within DOUBLE symlink root, request nested DEEP within...
		{
			name:  "relative root, relative nested request, direct, cwd deep within (double) symlink root",
			cwd:   filepath.Join(relativeViaDoubleLink, "path", "to"),
			root:  "../",
			input: "to/the/file.txt",
			// note: why not expect "path/to/the/file.txt" here?
			// this is because we don't know that the path used to access this path (which is a link within
			// the root) resides within the root. Without this information it appears as if this file resides
			// outside the root.
			expectedRealPath: filepath.Join(absolute, "path/to/the/file.txt"),
			//expectedRealPath:    "to/the/file.txt",
			expectedAccessPath: "to/the/file.txt",
		},
		{
			name:             "abs root, relative nested request, direct, cwd deep within (double) symlink root",
			cwd:              filepath.Join(relativeViaDoubleLink, "path", "to"),
			root:             filepath.Join(absoluteViaDoubleLink, "path"),
			input:            "to/the/file.txt",
			expectedRealPath: "to/the/file.txt",
		},
		{
			name:  "relative root, abs nested request, direct, cwd deep within (double) symlink root",
			cwd:   filepath.Join(relativeViaDoubleLink, "path", "to"),
			root:  "../",
			input: "/to/the/file.txt",
			// note: why not expect "path/to/the/file.txt" here?
			// this is because we don't know that the path used to access this path (which is a link within
			// the root) resides within the root. Without this information it appears as if this file resides
			// outside the root.
			expectedRealPath: filepath.Join(absolute, "path/to/the/file.txt"),
			//expectedRealPath:    "to/the/file.txt",
			expectedAccessPath: "to/the/file.txt",
		},
		{
			name:             "abs root, abs nested request, direct, cwd deep within (double) symlink root",
			cwd:              filepath.Join(relativeViaDoubleLink, "path", "to"),
			root:             filepath.Join(absoluteViaDoubleLink, "path"),
			input:            "/to/the/file.txt",
			expectedRealPath: "to/the/file.txt",
		},
		// link to outside of root cases...
		{
			name:               "relative root, relative request, abs indirect (outside of root)",
			root:               filepath.Join(relative, "path"),
			input:              "to/the/abs-outside.txt",
			expectedRealPath:   filepath.Join(absolute, "/somewhere/outside.txt"),
			expectedAccessPath: "to/the/abs-outside.txt",
		},
		{
			name:               "abs root, relative request, abs indirect (outside of root)",
			root:               filepath.Join(absolute, "path"),
			input:              "to/the/abs-outside.txt",
			expectedRealPath:   filepath.Join(absolute, "/somewhere/outside.txt"),
			expectedAccessPath: "to/the/abs-outside.txt",
		},
		{
			name:               "relative root, abs request, abs indirect (outside of root)",
			root:               filepath.Join(relative, "path"),
			input:              "/to/the/abs-outside.txt",
			expectedRealPath:   filepath.Join(absolute, "/somewhere/outside.txt"),
			expectedAccessPath: "to/the/abs-outside.txt",
		},
		{
			name:               "abs root, abs request, abs indirect (outside of root)",
			root:               filepath.Join(absolute, "path"),
			input:              "/to/the/abs-outside.txt",
			expectedRealPath:   filepath.Join(absolute, "/somewhere/outside.txt"),
			expectedAccessPath: "to/the/abs-outside.txt",
		},
		{
			name:               "relative root, relative request, relative indirect (outside of root)",
			root:               filepath.Join(relative, "path"),
			input:              "to/the/rel-outside.txt",
			expectedRealPath:   filepath.Join(absolute, "/somewhere/outside.txt"),
			expectedAccessPath: "to/the/rel-outside.txt",
		},
		{
			name:               "abs root, relative request, relative indirect (outside of root)",
			root:               filepath.Join(absolute, "path"),
			input:              "to/the/rel-outside.txt",
			expectedRealPath:   filepath.Join(absolute, "/somewhere/outside.txt"),
			expectedAccessPath: "to/the/rel-outside.txt",
		},
		{
			name:               "relative root, abs request, relative indirect (outside of root)",
			root:               filepath.Join(relative, "path"),
			input:              "/to/the/rel-outside.txt",
			expectedRealPath:   filepath.Join(absolute, "/somewhere/outside.txt"),
			expectedAccessPath: "to/the/rel-outside.txt",
		},
		{
			name:               "abs root, abs request, relative indirect (outside of root)",
			root:               filepath.Join(absolute, "path"),
			input:              "/to/the/rel-outside.txt",
			expectedRealPath:   filepath.Join(absolute, "/somewhere/outside.txt"),
			expectedAccessPath: "to/the/rel-outside.txt",
		},
		// link to outside of root cases... cwd within symlink root
		{
			name:               "relative root, relative request, abs indirect (outside of root), cwd within symlink root",
			cwd:                relativeViaLink,
			root:               "path",
			input:              "to/the/abs-outside.txt",
			expectedRealPath:   filepath.Join(absolute, "/somewhere/outside.txt"),
			expectedAccessPath: "to/the/abs-outside.txt",
		},
		{
			name:               "abs root, relative request, abs indirect (outside of root), cwd within symlink root",
			cwd:                relativeViaLink,
			root:               filepath.Join(absolute, "path"),
			input:              "to/the/abs-outside.txt",
			expectedRealPath:   filepath.Join(absolute, "/somewhere/outside.txt"),
			expectedAccessPath: "to/the/abs-outside.txt",
		},
		{
			name:               "relative root, abs request, abs indirect (outside of root), cwd within symlink root",
			cwd:                relativeViaLink,
			root:               "path",
			input:              "/to/the/abs-outside.txt",
			expectedRealPath:   filepath.Join(absolute, "/somewhere/outside.txt"),
			expectedAccessPath: "to/the/abs-outside.txt",
		},
		{
			name:               "abs root, abs request, abs indirect (outside of root), cwd within symlink root",
			cwd:                relativeViaLink,
			root:               filepath.Join(absolute, "path"),
			input:              "/to/the/abs-outside.txt",
			expectedRealPath:   filepath.Join(absolute, "/somewhere/outside.txt"),
			expectedAccessPath: "to/the/abs-outside.txt",
		},
		{
			name:               "relative root, relative request, relative indirect (outside of root), cwd within symlink root",
			cwd:                relativeViaLink,
			root:               "path",
			input:              "to/the/rel-outside.txt",
			expectedRealPath:   filepath.Join(absolute, "/somewhere/outside.txt"),
			expectedAccessPath: "to/the/rel-outside.txt",
		},
		{
			name:               "abs root, relative request, relative indirect (outside of root), cwd within symlink root",
			cwd:                relativeViaLink,
			root:               filepath.Join(absolute, "path"),
			input:              "to/the/rel-outside.txt",
			expectedRealPath:   filepath.Join(absolute, "/somewhere/outside.txt"),
			expectedAccessPath: "to/the/rel-outside.txt",
		},
		{
			name:               "relative root, abs request, relative indirect (outside of root), cwd within symlink root",
			cwd:                relativeViaLink,
			root:               "path",
			input:              "/to/the/rel-outside.txt",
			expectedRealPath:   filepath.Join(absolute, "/somewhere/outside.txt"),
			expectedAccessPath: "to/the/rel-outside.txt",
		},
		{
			name:               "abs root, abs request, relative indirect (outside of root), cwd within symlink root",
			cwd:                relativeViaLink,
			root:               filepath.Join(absolute, "path"),
			input:              "/to/the/rel-outside.txt",
			expectedRealPath:   filepath.Join(absolute, "/somewhere/outside.txt"),
			expectedAccessPath: "to/the/rel-outside.txt",
		},
		{
			name:               "relative root, relative request, relative indirect (outside of root), cwd within DOUBLE symlink root",
			cwd:                relativeViaDoubleLink,
			root:               "path",
			input:              "to/the/rel-outside.txt",
			expectedRealPath:   filepath.Join(absolute, "/somewhere/outside.txt"),
			expectedAccessPath: "to/the/rel-outside.txt",
		},
		{
			name:               "abs root, relative request, relative indirect (outside of root), cwd within DOUBLE symlink root",
			cwd:                relativeViaDoubleLink,
			root:               filepath.Join(absolute, "path"),
			input:              "to/the/rel-outside.txt",
			expectedRealPath:   filepath.Join(absolute, "/somewhere/outside.txt"),
			expectedAccessPath: "to/the/rel-outside.txt",
		},
		{
			name:               "relative root, abs request, relative indirect (outside of root), cwd within DOUBLE symlink root",
			cwd:                relativeViaDoubleLink,
			root:               "path",
			input:              "/to/the/rel-outside.txt",
			expectedRealPath:   filepath.Join(absolute, "/somewhere/outside.txt"),
			expectedAccessPath: "to/the/rel-outside.txt",
		},
		{
			name:               "abs root, abs request, relative indirect (outside of root), cwd within DOUBLE symlink root",
			cwd:                relativeViaDoubleLink,
			root:               filepath.Join(absolute, "path"),
			input:              "/to/the/rel-outside.txt",
			expectedRealPath:   filepath.Join(absolute, "/somewhere/outside.txt"),
			expectedAccessPath: "to/the/rel-outside.txt",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.expectedAccessPath == "" {
				c.expectedAccessPath = c.expectedRealPath
			}

			// we need to mimic a shell, otherwise we won't get a path within a symlink
			targetPath := filepath.Join(testDir, c.cwd)
			t.Setenv("PWD", filepath.Clean(targetPath))

			require.NoError(t, err)
			require.NoError(t, os.Chdir(targetPath))
			t.Cleanup(func() {
				require.NoError(t, os.Chdir(testDir))
			})

			resolver, err := NewFromDirectory(c.root, c.base)
			require.NoError(t, err)
			require.NotNil(t, resolver)

			refs, err := resolver.FilesByPath(c.input)
			require.NoError(t, err)
			if c.expectedRealPath == "" {
				require.Empty(t, refs)
				return
			}
			require.Len(t, refs, 1)
			assert.Equal(t, c.expectedRealPath, refs[0].RealPath, "real path different")
			assert.Equal(t, c.expectedAccessPath, refs[0].AccessPath, "virtual path different")
		})
	}
}

func TestDirectoryResolver_FilesByPath_relativeRoot(t *testing.T) {
	cases := []struct {
		name         string
		relativeRoot string
		input        string
		expected     []string
	}{
		{
			name:         "should find a file from an absolute input",
			relativeRoot: "./test-fixtures/",
			input:        "/image-symlinks/file-1.txt",
			expected: []string{
				"image-symlinks/file-1.txt",
			},
		},
		{
			name:         "should find a file from a relative path",
			relativeRoot: "./test-fixtures/",
			input:        "image-symlinks/file-1.txt",
			expected: []string{
				"image-symlinks/file-1.txt",
			},
		},
		{
			name: "should find a file from a relative path (root above cwd)",
			// TODO: refactor me! this test depends on the structure of the source dir not changing, which isn't great
			relativeRoot: "../",
			input:        "fileresolver/directory.go",
			expected: []string{
				"fileresolver/directory.go",
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resolver, err := NewFromDirectory(c.relativeRoot, "")
			assert.NoError(t, err)

			refs, err := resolver.FilesByPath(c.input)
			require.NoError(t, err)
			assert.Len(t, refs, len(c.expected))
			s := strset.New()
			for _, actual := range refs {
				s.Add(actual.RealPath)
			}
			assert.ElementsMatch(t, c.expected, s.List())
		})
	}
}

func TestDirectoryResolver_FilesByPath_absoluteRoot(t *testing.T) {
	cases := []struct {
		name         string
		relativeRoot string
		input        string
		expected     []string
	}{
		{
			name:         "should find a file from an absolute input",
			relativeRoot: "./test-fixtures/",
			input:        "/image-symlinks/file-1.txt",
			expected: []string{
				"image-symlinks/file-1.txt",
			},
		},
		{
			name:         "should find a file from a relative path",
			relativeRoot: "./test-fixtures/",
			input:        "image-symlinks/file-1.txt",
			expected: []string{
				"image-symlinks/file-1.txt",
			},
		},
		{
			name: "should find a file from a relative path (root above cwd)",
			// TODO: refactor me! this test depends on the structure of the source dir not changing, which isn't great
			relativeRoot: "../",
			input:        "fileresolver/directory.go",
			expected: []string{
				"fileresolver/directory.go",
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// note: this test is all about asserting correct functionality when the given analysis path
			// is an absolute path
			absRoot, err := filepath.Abs(c.relativeRoot)
			require.NoError(t, err)

			resolver, err := NewFromDirectory(absRoot, "")
			assert.NoError(t, err)

			refs, err := resolver.FilesByPath(c.input)
			require.NoError(t, err)
			assert.Len(t, refs, len(c.expected))
			s := strset.New()
			for _, actual := range refs {
				s.Add(actual.RealPath)
			}
			assert.ElementsMatch(t, c.expected, s.List())
		})
	}
}

func TestDirectoryResolver_FilesByPath(t *testing.T) {
	cases := []struct {
		name                 string
		root                 string
		input                string
		expected             string
		refCount             int
		forcePositiveHasPath bool
	}{
		{
			name:     "finds a file (relative)",
			root:     "./test-fixtures/",
			input:    "image-symlinks/file-1.txt",
			expected: "image-symlinks/file-1.txt",
			refCount: 1,
		},
		{
			name:     "finds a file with relative indirection",
			root:     "./test-fixtures/../test-fixtures",
			input:    "image-symlinks/file-1.txt",
			expected: "image-symlinks/file-1.txt",
			refCount: 1,
		},
		{
			name:     "managed non-existing files (relative)",
			root:     "./test-fixtures/",
			input:    "test-fixtures/image-symlinks/bogus.txt",
			refCount: 0,
		},
		{
			name:     "finds a file (absolute)",
			root:     "./test-fixtures/",
			input:    "/image-symlinks/file-1.txt",
			expected: "image-symlinks/file-1.txt",
			refCount: 1,
		},
		{
			name:                 "directories ignored",
			root:                 "./test-fixtures/",
			input:                "/image-symlinks",
			refCount:             0,
			forcePositiveHasPath: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resolver, err := NewFromDirectory(c.root, "")
			assert.NoError(t, err)

			hasPath := resolver.HasPath(c.input)
			if !c.forcePositiveHasPath {
				if c.refCount != 0 && !hasPath {
					t.Errorf("expected HasPath() to indicate existence, but did not")
				} else if c.refCount == 0 && hasPath {
					t.Errorf("expected HasPath() to NOT indicate existence, but does")
				}
			} else if !hasPath {
				t.Errorf("expected HasPath() to indicate existence, but did not (force path)")
			}

			refs, err := resolver.FilesByPath(c.input)
			require.NoError(t, err)
			assert.Len(t, refs, c.refCount)
			for _, actual := range refs {
				assert.Equal(t, c.expected, actual.RealPath)
			}
		})
	}
}

func TestDirectoryResolver_MultipleFilesByPath(t *testing.T) {
	cases := []struct {
		name     string
		input    []string
		refCount int
	}{
		{
			name:     "finds multiple files",
			input:    []string{"image-symlinks/file-1.txt", "image-symlinks/file-2.txt"},
			refCount: 2,
		},
		{
			name:     "skips non-existing files",
			input:    []string{"image-symlinks/bogus.txt", "image-symlinks/file-1.txt"},
			refCount: 1,
		},
		{
			name:     "does not return anything for non-existing directories",
			input:    []string{"non-existing/bogus.txt", "non-existing/file-1.txt"},
			refCount: 0,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resolver, err := NewFromDirectory("./test-fixtures", "")
			assert.NoError(t, err)
			refs, err := resolver.FilesByPath(c.input...)
			assert.NoError(t, err)

			if len(refs) != c.refCount {
				t.Errorf("unexpected number of refs: %d != %d", len(refs), c.refCount)
			}
		})
	}
}

func TestDirectoryResolver_FilesByGlobMultiple(t *testing.T) {
	resolver, err := NewFromDirectory("./test-fixtures", "")
	assert.NoError(t, err)
	refs, err := resolver.FilesByGlob("**/image-symlinks/file*")
	assert.NoError(t, err)

	assert.Len(t, refs, 2)
}

func TestDirectoryResolver_FilesByGlobRecursive(t *testing.T) {
	resolver, err := NewFromDirectory("./test-fixtures/image-symlinks", "")
	assert.NoError(t, err)
	refs, err := resolver.FilesByGlob("**/*.txt")
	assert.NoError(t, err)
	assert.Len(t, refs, 6)
}

func TestDirectoryResolver_FilesByGlobSingle(t *testing.T) {
	resolver, err := NewFromDirectory("./test-fixtures", "")
	assert.NoError(t, err)
	refs, err := resolver.FilesByGlob("**/image-symlinks/*1.txt")
	assert.NoError(t, err)

	assert.Len(t, refs, 1)
	assert.Equal(t, "image-symlinks/file-1.txt", refs[0].RealPath)
}

func TestDirectoryResolver_FilesByPath_ResolvesSymlinks(t *testing.T) {

	tests := []struct {
		name    string
		fixture string
	}{
		{
			name:    "one degree",
			fixture: "link_to_new_readme",
		},
		{
			name:    "two degrees",
			fixture: "link_to_link_to_new_readme",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver, err := NewFromDirectory("./test-fixtures/symlinks-simple", "")
			assert.NoError(t, err)

			refs, err := resolver.FilesByPath(test.fixture)
			require.NoError(t, err)
			assert.Len(t, refs, 1)

			reader, err := resolver.FileContentsByLocation(refs[0])
			require.NoError(t, err)

			actual, err := io.ReadAll(reader)
			require.NoError(t, err)

			expected, err := os.ReadFile("test-fixtures/symlinks-simple/readme")
			require.NoError(t, err)

			assert.Equal(t, string(expected), string(actual))
		})
	}
}

func TestDirectoryResolverDoesNotIgnoreRelativeSystemPaths(t *testing.T) {
	// let's make certain that "dev/place" is not ignored, since it is not "/dev/place"
	resolver, err := NewFromDirectory("test-fixtures/system_paths/target", "")
	assert.NoError(t, err)

	// all paths should be found (non filtering matches a path)
	locations, err := resolver.FilesByGlob("**/place")
	assert.NoError(t, err)
	// 4: within target/
	// 1: target/link --> relative path to "place" // NOTE: this is filtered out since it not unique relative to outside_root/link_target/place
	// 1: outside_root/link_target/place
	assert.Len(t, locations, 5)

	// ensure that symlink indexing outside of root worked
	testLocation := "test-fixtures/system_paths/outside_root/link_target/place"
	ok := false
	for _, location := range locations {
		if strings.HasSuffix(location.RealPath, testLocation) {
			ok = true
		}
	}

	if !ok {
		t.Fatalf("could not find test location=%q", testLocation)
	}
}

func Test_directoryResolver_FilesByMIMEType(t *testing.T) {
	tests := []struct {
		fixturePath   string
		mimeType      string
		expectedPaths *strset.Set
	}{
		{
			fixturePath:   "./test-fixtures/image-simple",
			mimeType:      "text/plain",
			expectedPaths: strset.New("file-1.txt", "file-2.txt", "target/really/nested/file-3.txt", "Dockerfile"),
		},
	}
	for _, test := range tests {
		t.Run(test.fixturePath, func(t *testing.T) {
			resolver, err := NewFromDirectory(test.fixturePath, "")
			assert.NoError(t, err)
			locations, err := resolver.FilesByMIMEType(test.mimeType)
			assert.NoError(t, err)
			assert.Equal(t, test.expectedPaths.Size(), len(locations))
			for _, l := range locations {
				assert.True(t, test.expectedPaths.Has(l.RealPath), "does not have path %q", l.RealPath)
			}
		})
	}
}

func Test_IndexingNestedSymLinks(t *testing.T) {
	resolver, err := NewFromDirectory("./test-fixtures/symlinks-simple", "")
	require.NoError(t, err)

	// check that we can get the real path
	locations, err := resolver.FilesByPath("./readme")
	require.NoError(t, err)
	assert.Len(t, locations, 1)

	// check that we can access the same file via 1 symlink
	locations, err = resolver.FilesByPath("./link_to_new_readme")
	require.NoError(t, err)
	require.Len(t, locations, 1)
	assert.Equal(t, "readme", locations[0].RealPath)
	assert.Equal(t, "link_to_new_readme", locations[0].AccessPath)

	// check that we can access the same file via 2 symlinks
	locations, err = resolver.FilesByPath("./link_to_link_to_new_readme")
	require.NoError(t, err)
	require.Len(t, locations, 1)
	assert.Equal(t, "readme", locations[0].RealPath)
	assert.Equal(t, "link_to_link_to_new_readme", locations[0].AccessPath)

	// check that we can access the same file via 2 symlinks
	locations, err = resolver.FilesByGlob("**/link_*")
	require.NoError(t, err)
	require.Len(t, locations, 1) // you would think this is 2, however, they point to the same file, and glob only returns unique files

	// returned locations can be in any order
	expectedAccessPaths := []string{
		"link_to_link_to_new_readme",
		//"link_to_new_readme", // we filter out this one because the first symlink resolves to the same file
	}

	expectedRealPaths := []string{
		"readme",
	}

	actualRealPaths := strset.New()
	actualAccessPaths := strset.New()
	for _, a := range locations {
		actualAccessPaths.Add(a.AccessPath)
		actualRealPaths.Add(a.RealPath)
	}

	assert.ElementsMatch(t, expectedAccessPaths, actualAccessPaths.List())
	assert.ElementsMatch(t, expectedRealPaths, actualRealPaths.List())
}

func Test_IndexingNestedSymLinks_ignoredIndexes(t *testing.T) {
	filterFn := func(_, path string, _ os.FileInfo, _ error) error {
		if strings.HasSuffix(path, string(filepath.Separator)+"readme") {
			return ErrSkipPath
		}
		return nil
	}

	resolver, err := NewFromDirectory("./test-fixtures/symlinks-simple", "", filterFn)
	require.NoError(t, err)

	// the path to the real file is PRUNED from the index, so we should NOT expect a location returned
	locations, err := resolver.FilesByPath("./readme")
	require.NoError(t, err)
	assert.Empty(t, locations)

	// check that we cannot access the file even via symlink
	locations, err = resolver.FilesByPath("./link_to_new_readme")
	require.NoError(t, err)
	assert.Empty(t, locations)

	// check that we still cannot access the same file via 2 symlinks
	locations, err = resolver.FilesByPath("./link_to_link_to_new_readme")
	require.NoError(t, err)
	assert.Empty(t, locations)
}

func Test_IndexingNestedSymLinksOutsideOfRoot(t *testing.T) {
	resolver, err := NewFromDirectory("./test-fixtures/symlinks-multiple-roots/root", "")
	require.NoError(t, err)

	// check that we can get the real path
	locations, err := resolver.FilesByPath("./readme")
	require.NoError(t, err)
	assert.Len(t, locations, 1)

	// check that we can access the same file via 2 symlinks (link_to_link_to_readme -> link_to_readme -> readme)
	locations, err = resolver.FilesByPath("./link_to_link_to_readme")
	require.NoError(t, err)
	assert.Len(t, locations, 1)

	// something looks wrong here
	t.Failed()
}

func Test_RootViaSymlink(t *testing.T) {
	resolver, err := NewFromDirectory("./test-fixtures/symlinked-root/nested/link-root", "")
	require.NoError(t, err)

	locations, err := resolver.FilesByPath("./file1.txt")
	require.NoError(t, err)
	assert.Len(t, locations, 1)

	locations, err = resolver.FilesByPath("./nested/file2.txt")
	require.NoError(t, err)
	assert.Len(t, locations, 1)

	locations, err = resolver.FilesByPath("./nested/linked-file1.txt")
	require.NoError(t, err)
	assert.Len(t, locations, 1)
}

func Test_directoryResolver_FileContentsByLocation(t *testing.T) {
	cwd, err := os.Getwd()
	require.NoError(t, err)

	r, err := NewFromDirectory(".", "")
	require.NoError(t, err)

	exists, existingPath, err := r.tree.File(stereoscopeFile.Path(filepath.Join(cwd, "test-fixtures/image-simple/file-1.txt")))
	require.True(t, exists)
	require.NoError(t, err)
	require.True(t, existingPath.HasReference())

	tests := []struct {
		name     string
		location file.Location
		expects  string
		err      bool
	}{
		{
			name:     "use file reference for content requests",
			location: file.NewLocationFromDirectory("some/place", *existingPath.Reference),
			expects:  "this file has contents",
		},
		{
			name:     "error on empty file reference",
			location: file.NewLocationFromDirectory("doesn't matter", stereoscopeFile.Reference{}),
			err:      true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			actual, err := r.FileContentsByLocation(test.location)
			if test.err {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			if test.expects != "" {
				b, err := io.ReadAll(actual)
				require.NoError(t, err)
				assert.Equal(t, test.expects, string(b))
			}
		})
	}
}

func Test_SymlinkLoopWithGlobsShouldResolve(t *testing.T) {
	test := func(t *testing.T) {
		resolver, err := NewFromDirectory("./test-fixtures/symlinks-loop", "")
		require.NoError(t, err)

		locations, err := resolver.FilesByGlob("**/file.target")
		require.NoError(t, err)

		require.Len(t, locations, 1)
		assert.Equal(t, "devices/loop0/file.target", locations[0].RealPath)
	}

	testWithTimeout(t, 5*time.Second, test)
}

func TestDirectoryResolver_FilesByPath_baseRoot(t *testing.T) {
	cases := []struct {
		name     string
		root     string
		input    string
		expected []string
	}{
		{
			name:  "should find the base file",
			root:  "./test-fixtures/symlinks-base/",
			input: "./base",
			expected: []string{
				"/base",
			},
		},
		{
			name:  "should follow a link with a pivoted root",
			root:  "./test-fixtures/symlinks-base/",
			input: "./foo",
			expected: []string{
				"/base",
			},
		},
		{
			name:  "should follow a relative link with extra parents",
			root:  "./test-fixtures/symlinks-base/",
			input: "./bar",
			expected: []string{
				"/base",
			},
		},
		{
			name:  "should follow an absolute link with extra parents",
			root:  "./test-fixtures/symlinks-base/",
			input: "./baz",
			expected: []string{
				"/base",
			},
		},
		{
			name:  "should follow an absolute link with extra parents",
			root:  "./test-fixtures/symlinks-base/",
			input: "./sub/link",
			expected: []string{
				"/sub/item",
			},
		},
		{
			name:  "should follow chained pivoted link",
			root:  "./test-fixtures/symlinks-base/",
			input: "./chain",
			expected: []string{
				"/base",
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resolver, err := NewFromDirectory(c.root, c.root)
			assert.NoError(t, err)

			refs, err := resolver.FilesByPath(c.input)
			require.NoError(t, err)
			assert.Len(t, refs, len(c.expected))
			s := strset.New()
			for _, actual := range refs {
				s.Add(actual.RealPath)
			}
			assert.ElementsMatch(t, c.expected, s.List())
		})
	}

}

func Test_directoryResolver_resolvesLinks(t *testing.T) {
	tests := []struct {
		name     string
		runner   func(file.Resolver) []file.Location
		expected []file.Location
	}{
		{
			name: "by mimetype",
			runner: func(resolver file.Resolver) []file.Location {
				// links should not show up when searching mimetype
				actualLocations, err := resolver.FilesByMIMEType("text/plain")
				assert.NoError(t, err)
				return actualLocations
			},
			expected: []file.Location{
				file.NewLocation("file-1.txt"),        // note: missing virtual path "file-1.txt"
				file.NewLocation("file-3.txt"),        // note: missing virtual path "file-3.txt"
				file.NewLocation("file-2.txt"),        // note: missing virtual path "file-2.txt"
				file.NewLocation("parent/file-4.txt"), // note: missing virtual path "file-4.txt"
			},
		},
		{
			name: "by glob to links",
			runner: func(resolver file.Resolver) []file.Location {
				// links are searched, but resolve to the real files
				// for that reason we need to place **/ in front (which is not the same for other resolvers)
				actualLocations, err := resolver.FilesByGlob("**/*ink-*")
				assert.NoError(t, err)
				return actualLocations
			},
			expected: []file.Location{
				file.NewVirtualLocation("file-1.txt", "link-1"),
				file.NewVirtualLocation("file-2.txt", "link-2"),
				// we already have this real file path via another link, so only one is returned
				//file.NewVirtualLocation("file-2.txt", "link-indirect"),
				file.NewVirtualLocation("file-3.txt", "link-within"),
			},
		},
		{
			name: "by basename",
			runner: func(resolver file.Resolver) []file.Location {
				// links are searched, but resolve to the real files
				actualLocations, err := resolver.FilesByGlob("**/file-2.txt")
				assert.NoError(t, err)
				return actualLocations
			},
			expected: []file.Location{
				// this has two copies in the base image, which overwrites the same location
				file.NewLocation("file-2.txt"), // note: missing virtual path "file-2.txt",
			},
		},
		{
			name: "by basename glob",
			runner: func(resolver file.Resolver) []file.Location {
				// links are searched, but resolve to the real files
				actualLocations, err := resolver.FilesByGlob("**/file-?.txt")
				assert.NoError(t, err)
				return actualLocations
			},
			expected: []file.Location{
				file.NewLocation("file-1.txt"),        // note: missing virtual path "file-1.txt"
				file.NewLocation("file-2.txt"),        // note: missing virtual path "file-2.txt"
				file.NewLocation("file-3.txt"),        // note: missing virtual path "file-3.txt"
				file.NewLocation("parent/file-4.txt"), // note: missing virtual path "parent/file-4.txt"
			},
		},
		{
			name: "by basename glob to links",
			runner: func(resolver file.Resolver) []file.Location {
				actualLocations, err := resolver.FilesByGlob("**/link-*")
				assert.NoError(t, err)
				return actualLocations
			},
			expected: []file.Location{
				file.NewVirtualLocation("file-1.txt", "link-1"),
				file.NewVirtualLocation("file-2.txt", "link-2"),

				// we already have this real file path via another link, so only one is returned
				//file.NewVirtualLocation("file-2.txt", "link-indirect"),

				file.NewVirtualLocation("file-3.txt", "link-within"),
			},
		},
		{
			name: "by extension",
			runner: func(resolver file.Resolver) []file.Location {
				// links are searched, but resolve to the real files
				actualLocations, err := resolver.FilesByGlob("**/*.txt")
				assert.NoError(t, err)
				return actualLocations
			},
			expected: []file.Location{
				file.NewLocation("file-1.txt"),        // note: missing virtual path "file-1.txt"
				file.NewLocation("file-2.txt"),        // note: missing virtual path "file-2.txt"
				file.NewLocation("file-3.txt"),        // note: missing virtual path "file-3.txt"
				file.NewLocation("parent/file-4.txt"), // note: missing virtual path "parent/file-4.txt"
			},
		},
		{
			name: "by path to degree 1 link",
			runner: func(resolver file.Resolver) []file.Location {
				// links resolve to the final file
				actualLocations, err := resolver.FilesByPath("/link-2")
				assert.NoError(t, err)
				return actualLocations
			},
			expected: []file.Location{
				// we have multiple copies across layers
				file.NewVirtualLocation("file-2.txt", "link-2"),
			},
		},
		{
			name: "by path to degree 2 link",
			runner: func(resolver file.Resolver) []file.Location {
				// multiple links resolves to the final file
				actualLocations, err := resolver.FilesByPath("/link-indirect")
				assert.NoError(t, err)
				return actualLocations
			},
			expected: []file.Location{
				// we have multiple copies across layers
				file.NewVirtualLocation("file-2.txt", "link-indirect"),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver, err := NewFromDirectory("./test-fixtures/symlinks-from-image-symlinks-fixture", "")
			require.NoError(t, err)
			assert.NoError(t, err)

			actual := test.runner(resolver)

			compareLocations(t, test.expected, actual)
		})
	}
}

func TestDirectoryResolver_DoNotAddVirtualPathsToTree(t *testing.T) {
	resolver, err := NewFromDirectory("./test-fixtures/symlinks-prune-indexing", "")
	require.NoError(t, err)

	var allRealPaths []stereoscopeFile.Path
	for l := range resolver.AllLocations(context.Background()) {
		allRealPaths = append(allRealPaths, stereoscopeFile.Path(l.RealPath))
	}
	pathSet := stereoscopeFile.NewPathSet(allRealPaths...)

	assert.False(t,
		pathSet.Contains("before-path/file.txt"),
		"symlink destinations should only be indexed at their real path, not through their virtual (symlinked) path",
	)

	assert.False(t,
		pathSet.Contains("a-path/file.txt"),
		"symlink destinations should only be indexed at their real path, not through their virtual (symlinked) path",
	)

}

func TestDirectoryResolver_FilesContents_errorOnDirRequest(t *testing.T) {
	defer goleak.VerifyNone(t)
	resolver, err := NewFromDirectory("./test-fixtures/system_paths", "")
	assert.NoError(t, err)

	var dirLoc *file.Location
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for loc := range resolver.AllLocations(ctx) {
		entry, err := resolver.index.Get(loc.Reference())
		require.NoError(t, err)
		if entry.Metadata.IsDir() {
			dirLoc = &loc
			break
		}
	}

	require.NotNil(t, dirLoc)

	reader, err := resolver.FileContentsByLocation(*dirLoc)
	require.Error(t, err)
	require.Nil(t, reader)
}

func TestDirectoryResolver_AllLocations(t *testing.T) {
	resolver, err := NewFromDirectory("./test-fixtures/symlinks-from-image-symlinks-fixture", "")
	assert.NoError(t, err)

	paths := strset.New()
	for loc := range resolver.AllLocations(context.Background()) {
		if strings.HasPrefix(loc.RealPath, "/") {
			// ignore outside the fixture root for now
			continue
		}
		paths.Add(loc.RealPath)
	}
	expected := []string{
		"file-1.txt",
		"file-2.txt",
		"file-3.txt",
		"link-1",
		"link-2",
		"link-dead",
		"link-indirect",
		"link-within",
		"parent",
		"parent-link",
		"parent/file-4.txt",
	}

	pathsList := paths.List()
	sort.Strings(pathsList)

	assert.ElementsMatchf(t, expected, pathsList, "expected all paths to be indexed, but found different paths: \n%s", cmp.Diff(expected, paths.List()))
}

func TestAllLocationsDoesNotLeakGoRoutine(t *testing.T) {
	defer goleak.VerifyNone(t)
	resolver, err := NewFromDirectory("./test-fixtures/symlinks-from-image-symlinks-fixture", "")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	for range resolver.AllLocations(ctx) {
		break
	}
	cancel()
}

var _ fs.FileInfo = (*testFileInfo)(nil)

type testFileInfo struct {
	mode os.FileMode
}

func (t testFileInfo) Name() string {
	panic("implement me")
}

func (t testFileInfo) Size() int64 {
	panic("implement me")
}

func (t testFileInfo) Mode() fs.FileMode {
	return t.mode
}

func (t testFileInfo) ModTime() time.Time {
	panic("implement me")
}

func (t testFileInfo) IsDir() bool {
	panic("implement me")
}

func (t testFileInfo) Sys() interface{} {
	panic("implement me")
}

// Tests for filetree resolver when single file is used for index
func TestFileResolver_FilesByPath(t *testing.T) {
	tests := []struct {
		description        string
		filePath           string // relative to cwd
		fileByPathInput    string
		expectedRealPath   string
		expectedAccessPath string
		cwd                string
	}{
		{
			description:        "Finds file if searched by filepath",
			filePath:           "./test-fixtures/req-resp/path/to/the/file.txt",
			fileByPathInput:    "file.txt",
			expectedRealPath:   "/file.txt",
			expectedAccessPath: "/file.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			parentPath, err := absoluteSymlinkFreePathToParent(tt.filePath)
			require.NoError(t, err)
			require.NotNil(t, parentPath)

			resolver, err := NewFromFile(parentPath, tt.filePath)
			require.NoError(t, err)
			require.NotNil(t, resolver)

			refs, err := resolver.FilesByPath(tt.fileByPathInput)
			require.NoError(t, err)
			if tt.expectedRealPath == "" {
				require.Empty(t, refs)
				return
			}
			require.Len(t, refs, 1)
			assert.Equal(t, tt.expectedRealPath, refs[0].RealPath, "real path different")
			assert.Equal(t, tt.expectedAccessPath, refs[0].AccessPath, "virtual path different")
		})
	}
}

func TestFileResolver_MultipleFilesByPath(t *testing.T) {
	tests := []struct {
		description string
		input       []string
		refCount    int
	}{
		{
			description: "finds file ",
			input:       []string{"file.txt"},
			refCount:    1,
		},
		{
			description: "skip non-existing files",
			input:       []string{"file.txt", "bogus.txt"},
			refCount:    1,
		},
		{
			description: "does not return anything for non-existing files",
			input:       []string{"non-existing/bogus.txt", "another-bogus.txt"},
			refCount:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			filePath := "./test-fixtures/req-resp/path/to/the/file.txt"
			parentPath, err := absoluteSymlinkFreePathToParent(filePath)
			require.NoError(t, err)
			require.NotNil(t, parentPath)

			resolver, err := NewFromFile(parentPath, filePath)
			assert.NoError(t, err)
			refs, err := resolver.FilesByPath(tt.input...)
			assert.NoError(t, err)

			if len(refs) != tt.refCount {
				t.Errorf("unexpected number of refs: %d != %d", len(refs), tt.refCount)
			}
		})
	}
}

func TestFileResolver_FilesByGlob(t *testing.T) {
	filePath := "./test-fixtures/req-resp/path/to/the/file.txt"
	parentPath, err := absoluteSymlinkFreePathToParent(filePath)
	require.NoError(t, err)
	require.NotNil(t, parentPath)

	resolver, err := NewFromFile(parentPath, filePath)
	assert.NoError(t, err)
	refs, err := resolver.FilesByGlob("*.txt")
	assert.NoError(t, err)

	assert.Len(t, refs, 1)
}

func Test_fileResolver_FilesByMIMEType(t *testing.T) {
	tests := []struct {
		fixturePath   string
		mimeType      string
		expectedPaths *strset.Set
	}{
		{
			fixturePath:   "./test-fixtures/image-simple/file-1.txt",
			mimeType:      "text/plain",
			expectedPaths: strset.New("/file-1.txt"),
		},
	}
	for _, test := range tests {
		t.Run(test.fixturePath, func(t *testing.T) {
			filePath := "./test-fixtures/image-simple/file-1.txt"
			parentPath, err := absoluteSymlinkFreePathToParent(filePath)
			require.NoError(t, err)
			require.NotNil(t, parentPath)

			resolver, err := NewFromFile(parentPath, filePath)
			assert.NoError(t, err)
			locations, err := resolver.FilesByMIMEType(test.mimeType)
			assert.NoError(t, err)
			assert.Equal(t, test.expectedPaths.Size(), len(locations))
			for _, l := range locations {
				assert.True(t, test.expectedPaths.Has(l.RealPath), "does not have path %q", l.RealPath)
			}
		})
	}
}

func Test_fileResolver_FileContentsByLocation(t *testing.T) {
	cwd, err := os.Getwd()
	require.NoError(t, err)

	filePath := "./test-fixtures/image-simple/file-1.txt"
	parentPath, err := absoluteSymlinkFreePathToParent(filePath)
	require.NoError(t, err)
	require.NotNil(t, parentPath)

	r, err := NewFromFile(parentPath, filePath)
	require.NoError(t, err)

	exists, existingPath, err := r.tree.File(stereoscopeFile.Path(filepath.Join(cwd, "test-fixtures/image-simple/file-1.txt")))
	require.True(t, exists)
	require.NoError(t, err)
	require.True(t, existingPath.HasReference())

	tests := []struct {
		name     string
		location file.Location
		expects  string
		err      bool
	}{
		{
			name:     "use file reference for content requests",
			location: file.NewLocationFromDirectory("some/place", *existingPath.Reference),
			expects:  "this file has contents",
		},
		{
			name:     "error on empty file reference",
			location: file.NewLocationFromDirectory("doesn't matter", stereoscopeFile.Reference{}),
			err:      true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			actual, err := r.FileContentsByLocation(test.location)
			if test.err {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			if test.expects != "" {
				b, err := io.ReadAll(actual)
				require.NoError(t, err)
				assert.Equal(t, test.expects, string(b))
			}
		})
	}
}

func TestFileResolver_AllLocations_errorOnDirRequest(t *testing.T) {
	defer goleak.VerifyNone(t)

	filePath := "./test-fixtures/system_paths/target/home/place"
	parentPath, err := absoluteSymlinkFreePathToParent(filePath)
	require.NoError(t, err)
	require.NotNil(t, parentPath)
	resolver, err := NewFromFile(parentPath, filePath)
	require.NoError(t, err)

	var dirLoc *file.Location
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for loc := range resolver.AllLocations(ctx) {
		entry, err := resolver.index.Get(loc.Reference())
		require.NoError(t, err)
		if entry.Metadata.IsDir() {
			dirLoc = &loc
			break
		}
	}

	require.NotNil(t, dirLoc)

	reader, err := resolver.FileContentsByLocation(*dirLoc)
	require.Error(t, err)
	require.Nil(t, reader)
}

func TestFileResolver_AllLocations(t *testing.T) {
	// Verify both the parent and the file itself are indexed
	filePath := "./test-fixtures/system_paths/target/home/place"
	parentPath, err := absoluteSymlinkFreePathToParent(filePath)
	require.NoError(t, err)
	require.NotNil(t, parentPath)
	resolver, err := NewFromFile(parentPath, filePath)
	require.NoError(t, err)

	paths := strset.New()
	for loc := range resolver.AllLocations(context.Background()) {
		paths.Add(loc.RealPath)
	}
	expected := []string{
		"/place",
		"", // This is how we see the parent dir, since we're resolving wrt the parent directory.
	}

	pathsList := paths.List()
	sort.Strings(pathsList)

	assert.ElementsMatchf(t, expected, pathsList, "expected all paths to be indexed, but found different paths: \n%s", cmp.Diff(expected, paths.List()))
}

func Test_FileResolver_AllLocationsDoesNotLeakGoRoutine(t *testing.T) {
	defer goleak.VerifyNone(t)
	filePath := "./test-fixtures/system_paths/target/home/place"
	parentPath, err := absoluteSymlinkFreePathToParent(filePath)
	require.NoError(t, err)
	require.NotNil(t, parentPath)
	resolver, err := NewFromFile(parentPath, filePath)
	require.NoError(t, err)

	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	for range resolver.AllLocations(ctx) {
		break
	}
	cancel()
}
