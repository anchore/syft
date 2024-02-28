//go:build !windows
// +build !windows

package fileresolver

import (
	"context"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/file"
)

func Test_UnindexDirectoryResolver_RequestRelativePathWithinSymlink(t *testing.T) {
	pwd, err := os.Getwd()

	// we need to mimic a shell, otherwise we won't get a path within a symlink
	targetPath := filepath.Join(pwd, "./test-fixtures/symlinked-root/nested/link-root/nested")
	t.Setenv("PWD", targetPath)

	require.NoError(t, err)
	require.NoError(t, os.Chdir(targetPath))
	t.Cleanup(func() {
		require.NoError(t, os.Chdir(pwd))
	})

	resolver := NewFromUnindexedDirectory("./")
	require.NoError(t, err)

	locations, err := resolver.FilesByPath("file2.txt")
	require.NoError(t, err)
	require.Len(t, locations, 1)

	// TODO: this is technically not correct behavior since this is reporting the symlink path (virtual path) and
	// not the real path.
	require.False(t, filepath.IsAbs(locations[0].RealPath), "should be relative path")
}

func Test_UnindexDirectoryResolver_FilesByPath_request_response(t *testing.T) {
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
		expectedAccessPath string // if empty, the virtual path should be the same as the real path
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
			// note: this is inconsistent with the directory resolver. The real path is essentially the virtual path
			// in this case for the unindexed resolver, which is not correct.
			expectedRealPath: "path/to/the/file.txt",
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
			// note: this is inconsistent with the directory resolver. The real path is essentially the virtual path
			// in this case for the unindexed resolver, which is not correct.
			expectedRealPath: "path/to/the/file.txt",
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
			// note: this is inconsistent with the directory resolver. The real path is essentially the virtual path
			// in this case for the unindexed resolver, which is not correct.
			expectedRealPath: "to/the/file.txt",
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
			// note: this is inconsistent with the directory resolver. The real path is essentially the virtual path
			// in this case for the unindexed resolver, which is not correct.
			expectedRealPath: "to/the/file.txt",
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
			// note: this is inconsistent with the directory resolver. The real path is essentially the virtual path
			// in this case for the unindexed resolver, which is not correct.
			expectedRealPath: "path/to/the/file.txt",
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
			// note: this is inconsistent with the directory resolver. The real path is essentially the virtual path
			// in this case for the unindexed resolver, which is not correct.
			expectedRealPath: "path/to/the/file.txt",
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
			// note: this is inconsistent with the directory resolver. The real path is essentially the virtual path
			// in this case for the unindexed resolver, which is not correct.
			expectedRealPath: "to/the/file.txt",
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
			// note: this is inconsistent with the directory resolver. The real path is essentially the virtual path
			// in this case for the unindexed resolver, which is not correct.
			expectedRealPath: "to/the/file.txt",
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
			// note: this is inconsistent with the directory resolver. The real path is essentially the virtual path
			// in this case for the unindexed resolver, which is not correct.
			expectedRealPath: "to/the/file.txt",
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
			// note: this is inconsistent with the directory resolver. The real path is essentially the virtual path
			// in this case for the unindexed resolver, which is not correct.
			expectedRealPath: "to/the/file.txt",
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
			name:  "relative root, relative request, relative indirect (outside of root)",
			root:  filepath.Join(relative, "path"),
			input: "to/the/rel-outside.txt",
			//expectedRealPath:    filepath.Join(absolute, "/somewhere/outside.txt"),
			// TODO: the real path is not correct
			expectedRealPath:   "../somewhere/outside.txt",
			expectedAccessPath: "to/the/rel-outside.txt",
		},
		{
			name:  "abs root, relative request, relative indirect (outside of root)",
			root:  filepath.Join(absolute, "path"),
			input: "to/the/rel-outside.txt",
			//expectedRealPath:    filepath.Join(absolute, "/somewhere/outside.txt"),
			// TODO: the real path is not correct
			expectedRealPath:   "../somewhere/outside.txt",
			expectedAccessPath: "to/the/rel-outside.txt",
		},
		{
			name:  "relative root, abs request, relative indirect (outside of root)",
			root:  filepath.Join(relative, "path"),
			input: "/to/the/rel-outside.txt",
			//expectedRealPath:    filepath.Join(absolute, "/somewhere/outside.txt"),
			// TODO: the real path is not correct
			expectedRealPath:   "../somewhere/outside.txt",
			expectedAccessPath: "to/the/rel-outside.txt",
		},
		{
			name:  "abs root, abs request, relative indirect (outside of root)",
			root:  filepath.Join(absolute, "path"),
			input: "/to/the/rel-outside.txt",
			//expectedRealPath:    filepath.Join(absolute, "/somewhere/outside.txt"),
			// TODO: the real path is not correct
			expectedRealPath:   "../somewhere/outside.txt",
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
			name:  "relative root, relative request, relative indirect (outside of root), cwd within symlink root",
			cwd:   relativeViaLink,
			root:  "path",
			input: "to/the/rel-outside.txt",
			//expectedRealPath:    filepath.Join(absolute, "/somewhere/outside.txt"),
			// TODO: the real path is not correct
			expectedRealPath:   "../somewhere/outside.txt",
			expectedAccessPath: "to/the/rel-outside.txt",
		},
		{
			name:  "abs root, relative request, relative indirect (outside of root), cwd within symlink root",
			cwd:   relativeViaLink,
			root:  filepath.Join(absolute, "path"),
			input: "to/the/rel-outside.txt",
			//expectedRealPath:    filepath.Join(absolute, "/somewhere/outside.txt"),
			// TODO: the real path is not correct
			expectedRealPath:   "../somewhere/outside.txt",
			expectedAccessPath: "to/the/rel-outside.txt",
		},
		{
			name:  "relative root, abs request, relative indirect (outside of root), cwd within symlink root",
			cwd:   relativeViaLink,
			root:  "path",
			input: "/to/the/rel-outside.txt",
			//expectedRealPath:    filepath.Join(absolute, "/somewhere/outside.txt"),
			// TODO: the real path is not correct
			expectedRealPath:   "../somewhere/outside.txt",
			expectedAccessPath: "to/the/rel-outside.txt",
		},
		{
			name:  "abs root, abs request, relative indirect (outside of root), cwd within symlink root",
			cwd:   relativeViaLink,
			root:  filepath.Join(absolute, "path"),
			input: "/to/the/rel-outside.txt",
			//expectedRealPath:    filepath.Join(absolute, "/somewhere/outside.txt"),
			// TODO: the real path is not correct
			expectedRealPath:   "../somewhere/outside.txt",
			expectedAccessPath: "to/the/rel-outside.txt",
		},
		{
			name:  "relative root, relative request, relative indirect (outside of root), cwd within DOUBLE symlink root",
			cwd:   relativeViaDoubleLink,
			root:  "path",
			input: "to/the/rel-outside.txt",
			//expectedRealPath:    filepath.Join(absolute, "/somewhere/outside.txt"),
			// TODO: the real path is not correct
			expectedRealPath:   "../somewhere/outside.txt",
			expectedAccessPath: "to/the/rel-outside.txt",
		},
		{
			name:  "abs root, relative request, relative indirect (outside of root), cwd within DOUBLE symlink root",
			cwd:   relativeViaDoubleLink,
			root:  filepath.Join(absolute, "path"),
			input: "to/the/rel-outside.txt",
			//expectedRealPath:    filepath.Join(absolute, "/somewhere/outside.txt"),
			// TODO: the real path is not correct
			expectedRealPath:   "../somewhere/outside.txt",
			expectedAccessPath: "to/the/rel-outside.txt",
		},
		{
			name:  "relative root, abs request, relative indirect (outside of root), cwd within DOUBLE symlink root",
			cwd:   relativeViaDoubleLink,
			root:  "path",
			input: "/to/the/rel-outside.txt",
			//expectedRealPath:    filepath.Join(absolute, "/somewhere/outside.txt"),
			// TODO: the real path is not correct
			expectedRealPath:   "../somewhere/outside.txt",
			expectedAccessPath: "to/the/rel-outside.txt",
		},
		{
			name:  "abs root, abs request, relative indirect (outside of root), cwd within DOUBLE symlink root",
			cwd:   relativeViaDoubleLink,
			root:  filepath.Join(absolute, "path"),
			input: "/to/the/rel-outside.txt",
			//expectedRealPath:    filepath.Join(absolute, "/somewhere/outside.txt"),
			// TODO: the real path is not correct
			expectedRealPath:   "../somewhere/outside.txt",
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

			resolver := NewFromUnindexedDirectory(c.root)
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

func Test_UnindexedDirectoryResolver_Basic(t *testing.T) {
	wd, err := os.Getwd()
	require.NoError(t, err)

	r := NewFromUnindexedDirectory(path.Join(wd, "test-fixtures"))
	locations, err := r.FilesByGlob("image-symlinks/*")
	require.NoError(t, err)
	require.Len(t, locations, 5)
}

func Test_UnindexedDirectoryResolver_NoGoroutineLeak(t *testing.T) {
	defer goleak.VerifyNone(t)
	wd, err := os.Getwd()
	require.NoError(t, err)

	r := NewFromUnindexedDirectory(path.Join(wd, "test-fixtures"))
	ctx, cancel := context.WithCancel(context.Background())
	for range r.AllLocations(ctx) {
		break
	}
	cancel()
}

func Test_UnindexedDirectoryResolver_FilesByPath_relativeRoot(t *testing.T) {
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
			input:        "fileresolver/deferred.go",
			expected: []string{
				"fileresolver/deferred.go",
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resolver := NewFromUnindexedDirectory(c.relativeRoot)

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

func Test_UnindexedDirectoryResolver_FilesByPath_absoluteRoot(t *testing.T) {
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

			resolver := NewFromUnindexedDirectory(absRoot)
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

func Test_UnindexedDirectoryResolver_FilesByPath(t *testing.T) {
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
			resolver := NewFromUnindexedDirectory(c.root)

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

func Test_UnindexedDirectoryResolver_MultipleFilesByPath(t *testing.T) {
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
			resolver := NewFromUnindexedDirectory("./test-fixtures")
			refs, err := resolver.FilesByPath(c.input...)
			assert.NoError(t, err)

			if len(refs) != c.refCount {
				t.Errorf("unexpected number of refs: %d != %d", len(refs), c.refCount)
			}
		})
	}
}

func Test_UnindexedDirectoryResolver_FilesByGlobMultiple(t *testing.T) {
	resolver := NewFromUnindexedDirectory("./test-fixtures")
	refs, err := resolver.FilesByGlob("**/image-symlinks/file*")
	assert.NoError(t, err)

	assert.Len(t, refs, 2)
}

func Test_UnindexedDirectoryResolver_FilesByGlobRecursive(t *testing.T) {
	resolver := NewFromUnindexedDirectory("./test-fixtures/image-symlinks")
	refs, err := resolver.FilesByGlob("**/*.txt")
	assert.NoError(t, err)
	assert.Len(t, refs, 6)
}

func Test_UnindexedDirectoryResolver_FilesByGlobSingle(t *testing.T) {
	resolver := NewFromUnindexedDirectory("./test-fixtures")
	refs, err := resolver.FilesByGlob("**/image-symlinks/*1.txt")
	assert.NoError(t, err)

	assert.Len(t, refs, 1)
	assert.Equal(t, "image-symlinks/file-1.txt", refs[0].RealPath)
}

func Test_UnindexedDirectoryResolver_FilesByPath_ResolvesSymlinks(t *testing.T) {

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
			resolver := NewFromUnindexedDirectory("./test-fixtures/symlinks-simple")

			refs, err := resolver.FilesByPath(test.fixture)
			require.NoError(t, err)
			require.Len(t, refs, 1)

			reader, err := resolver.FileContentsByLocation(refs[0])
			require.NoError(t, err)

			actual, err := io.ReadAll(reader)
			require.NoError(t, err)

			expected, err := os.ReadFile("test-fixtures/symlinks-simple/readme")
			require.NoError(t, err)

			require.Equal(t, string(expected), string(actual))
		})
	}
}

func Test_UnindexedDirectoryResolverDoesNotIgnoreRelativeSystemPaths(t *testing.T) {
	// let's make certain that "dev/place" is not ignored, since it is not "/dev/place"
	resolver := NewFromUnindexedDirectory("test-fixtures/system_paths/target")

	// all paths should be found (non filtering matches a path)
	locations, err := resolver.FilesByGlob("**/place")
	assert.NoError(t, err)
	// 4: within target/
	// 1: target/link --> relative path to "place" // NOTE: this is filtered out since it not unique relative to outside_root/link_target/place
	// 1: outside_root/link_target/place
	assert.Len(t, locations, 5)

	// ensure that symlink indexing outside of root worked
	testLocation := "../outside_root/link_target/place"
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

func Test_UnindexedDirectoryResover_IndexingNestedSymLinks(t *testing.T) {
	resolver := NewFromUnindexedDirectory("./test-fixtures/symlinks-simple")

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

func Test_UnindexedDirectoryResover_IndexingNestedSymLinksOutsideOfRoot(t *testing.T) {
	resolver := NewFromUnindexedDirectory("./test-fixtures/symlinks-multiple-roots/root")

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

func Test_UnindexedDirectoryResover_RootViaSymlink(t *testing.T) {
	resolver := NewFromUnindexedDirectory("./test-fixtures/symlinked-root/nested/link-root")

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

func Test_UnindexedDirectoryResolver_FileContentsByLocation(t *testing.T) {
	cwd, err := os.Getwd()
	require.NoError(t, err)

	r := NewFromUnindexedDirectory(path.Join(cwd, "test-fixtures/image-simple"))
	require.NoError(t, err)

	tests := []struct {
		name     string
		location file.Location
		expects  string
		err      bool
	}{
		{
			name:     "use file reference for content requests",
			location: file.NewLocation("file-1.txt"),
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

func Test_UnindexedDirectoryResover_SymlinkLoopWithGlobsShouldResolve(t *testing.T) {
	test := func(t *testing.T) {
		resolver := NewFromUnindexedDirectory("./test-fixtures/symlinks-loop")

		locations, err := resolver.FilesByGlob("**/file.target")
		require.NoError(t, err)

		require.Len(t, locations, 1)
		assert.Equal(t, "devices/loop0/file.target", locations[0].RealPath)
	}

	testWithTimeout(t, 5*time.Second, test)
}

func Test_UnindexedDirectoryResolver_FilesByPath_baseRoot(t *testing.T) {
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
				"base",
			},
		},
		{
			name:  "should follow a link with a pivoted root",
			root:  "./test-fixtures/symlinks-base/",
			input: "./foo",
			expected: []string{
				"base",
			},
		},
		{
			name:  "should follow a relative link with extra parents",
			root:  "./test-fixtures/symlinks-base/",
			input: "./bar",
			expected: []string{
				"base",
			},
		},
		{
			name:  "should follow an absolute link with extra parents",
			root:  "./test-fixtures/symlinks-base/",
			input: "./baz",
			expected: []string{
				"base",
			},
		},
		{
			name:  "should follow an absolute link with extra parents",
			root:  "./test-fixtures/symlinks-base/",
			input: "./sub/link",
			expected: []string{
				"sub/item",
			},
		},
		{
			name:  "should follow chained pivoted link",
			root:  "./test-fixtures/symlinks-base/",
			input: "./chain",
			expected: []string{
				"base",
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resolver := NewFromRootedUnindexedDirectory(c.root, c.root)

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

func Test_UnindexedDirectoryResolver_resolvesLinks(t *testing.T) {
	tests := []struct {
		name     string
		runner   func(file.Resolver) []file.Location
		expected []file.Location
	}{
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
				// file.NewVirtualLocation("file-2.txt", "link-indirect"),
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
				file.NewLocation("file-2.txt"),
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
				file.NewLocation("file-1.txt"),
				file.NewLocation("file-2.txt"),
				file.NewLocation("file-3.txt"),
				file.NewVirtualLocation("parent/file-4.txt", "parent-link/file-4.txt"),
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
				file.NewVirtualLocationFromDirectory("file-1.txt", "link-1", stereoscopeFile.Reference{RealPath: "file-1.txt"}),
				file.NewVirtualLocationFromDirectory("file-2.txt", "link-2", stereoscopeFile.Reference{RealPath: "file-2.txt"}),
				// we already have this real file path via another link, so only one is returned
				//file.NewVirtualLocationFromDirectory("file-2.txt", "link-indirect", stereoscopeFile.Reference{RealPath: "file-2.txt"}),
				file.NewVirtualLocationFromDirectory("file-3.txt", "link-within", stereoscopeFile.Reference{RealPath: "file-3.txt"}),
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
				file.NewLocation("file-1.txt"),
				file.NewLocation("file-2.txt"),
				file.NewLocation("file-3.txt"),
				file.NewVirtualLocation("parent/file-4.txt", "parent-link/file-4.txt"),
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
			resolver := NewFromUnindexedDirectory("./test-fixtures/symlinks-from-image-symlinks-fixture")

			actual := test.runner(resolver)

			compareLocations(t, test.expected, actual)
		})
	}
}

func Test_UnindexedDirectoryResolver_DoNotAddVirtualPathsToTree(t *testing.T) {
	resolver := NewFromUnindexedDirectory("./test-fixtures/symlinks-prune-indexing")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	allLocations := resolver.AllLocations(ctx)
	var allRealPaths []stereoscopeFile.Path
	for l := range allLocations {
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

func Test_UnindexedDirectoryResolver_FilesContents_errorOnDirRequest(t *testing.T) {
	resolver := NewFromUnindexedDirectory("./test-fixtures/system_paths")

	dirLoc := file.NewLocation("arg/foo")

	reader, err := resolver.FileContentsByLocation(dirLoc)
	require.Error(t, err)
	require.Nil(t, reader)
}

func Test_UnindexedDirectoryResolver_AllLocations(t *testing.T) {
	resolver := NewFromUnindexedDirectory("./test-fixtures/symlinks-from-image-symlinks-fixture")

	paths := strset.New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for loc := range resolver.AllLocations(ctx) {
		if strings.HasPrefix(loc.RealPath, "/") {
			// ignore outside of the fixture root for now
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

func Test_WritableUnindexedDirectoryResolver(t *testing.T) {
	tmpdir := t.TempDir()

	p := "some/path/file"
	c := "some contents"

	dr := NewFromUnindexedDirectory(tmpdir)

	locations, err := dr.FilesByPath(p)
	require.NoError(t, err)
	require.Len(t, locations, 0)

	err = dr.Write(file.NewLocation(p), strings.NewReader(c))
	require.NoError(t, err)

	locations, err = dr.FilesByPath(p)
	require.NoError(t, err)
	require.Len(t, locations, 1)

	reader, err := dr.FileContentsByLocation(locations[0])
	require.NoError(t, err)
	bytes, err := io.ReadAll(reader)
	require.Equal(t, c, string(bytes))
}

func testWithTimeout(t *testing.T, timeout time.Duration, test func(*testing.T)) {
	done := make(chan bool)
	go func() {
		test(t)
		done <- true
	}()

	select {
	case <-time.After(timeout):
		t.Fatal("test timed out")
	case <-done:
	}
}
