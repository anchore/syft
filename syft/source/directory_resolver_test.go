//go:build !windows
// +build !windows

package source

import (
	"io"
	"io/fs"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/stretchr/testify/assert"
	"github.com/wagoodman/go-progress"
)

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
			name:         "should find a file from a relative path (root above cwd)",
			relativeRoot: "../",
			input:        "sbom/sbom.go",
			expected: []string{
				"sbom/sbom.go",
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resolver, err := newDirectoryResolver(c.relativeRoot)
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
			name:         "should find a file from a relative path (root above cwd)",
			relativeRoot: "../",
			input:        "sbom/sbom.go",
			expected: []string{
				"sbom/sbom.go",
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// note: this test is all about asserting correct functionality when the given analysis path
			// is an absolute path
			absRoot, err := filepath.Abs(c.relativeRoot)
			require.NoError(t, err)

			resolver, err := newDirectoryResolver(absRoot)
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
			resolver, err := newDirectoryResolver(c.root)
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
			resolver, err := newDirectoryResolver("./test-fixtures")
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
	resolver, err := newDirectoryResolver("./test-fixtures")
	assert.NoError(t, err)
	refs, err := resolver.FilesByGlob("**/image-symlinks/file*")
	assert.NoError(t, err)

	assert.Len(t, refs, 2)
}

func TestDirectoryResolver_FilesByGlobRecursive(t *testing.T) {
	resolver, err := newDirectoryResolver("./test-fixtures/image-symlinks")
	assert.NoError(t, err)
	refs, err := resolver.FilesByGlob("**/*.txt")
	assert.NoError(t, err)
	assert.Len(t, refs, 6)
}

func TestDirectoryResolver_FilesByGlobSingle(t *testing.T) {
	resolver, err := newDirectoryResolver("./test-fixtures")
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
			resolver, err := newDirectoryResolver("./test-fixtures/symlinks-simple")
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
	resolver, err := newDirectoryResolver("test-fixtures/system_paths/target")
	assert.NoError(t, err)
	// ensure the correct filter function is wired up by default
	expectedFn := reflect.ValueOf(isUnallowableFileType)
	actualFn := reflect.ValueOf(resolver.pathFilterFns[0])
	assert.Equal(t, expectedFn.Pointer(), actualFn.Pointer())

	// all paths should be found (non filtering matches a path)
	locations, err := resolver.FilesByGlob("**/place")
	assert.NoError(t, err)
	// 4: within target/
	// 1: target/link --> relative path to "place"
	// 1: outside_root/link_target/place
	assert.Len(t, locations, 6)

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

func Test_isUnallowableFileType(t *testing.T) {
	tests := []struct {
		name     string
		info     os.FileInfo
		expected bool
	}{
		{
			name: "regular file",
			info: testFileInfo{
				mode: 0,
			},
			expected: false,
		},
		{
			name: "dir",
			info: testFileInfo{
				mode: os.ModeDir,
			},
			expected: false,
		},
		{
			name: "symlink",
			info: testFileInfo{
				mode: os.ModeSymlink,
			},
			expected: false,
		},
		{
			name: "socket",
			info: testFileInfo{
				mode: os.ModeSocket,
			},
			expected: true,
		},
		{
			name: "named pipe",
			info: testFileInfo{
				mode: os.ModeNamedPipe,
			},
			expected: true,
		},
		{
			name: "char device",
			info: testFileInfo{
				mode: os.ModeCharDevice,
			},
			expected: true,
		},
		{
			name: "block device",
			info: testFileInfo{
				mode: os.ModeDevice,
			},
			expected: true,
		},
		{
			name: "irregular",
			info: testFileInfo{
				mode: os.ModeIrregular,
			},
			expected: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, isUnallowableFileType("dont/care", test.info))
		})
	}
}

func Test_directoryResolver_index(t *testing.T) {
	// note: this test is testing the effects from newDirectoryResolver, indexTree, and addPathToIndex
	r, err := newDirectoryResolver("test-fixtures/system_paths/target")
	if err != nil {
		t.Fatalf("unable to get indexed dir resolver: %+v", err)
	}
	tests := []struct {
		name string
		path string
	}{
		{
			name: "has dir",
			path: "test-fixtures/system_paths/target/home",
		},
		{
			name: "has path",
			path: "test-fixtures/system_paths/target/home/place",
		},
		{
			name: "has symlink",
			path: "test-fixtures/system_paths/target/link/a-symlink",
		},
		{
			name: "has symlink target",
			path: "test-fixtures/system_paths/outside_root/link_target/place",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			info, err := os.Stat(test.path)
			assert.NoError(t, err)

			// note: the index uses absolute paths, so assertions MUST keep this in mind
			cwd, err := os.Getwd()
			require.NoError(t, err)

			p := file.Path(path.Join(cwd, test.path))
			assert.Equal(t, true, r.fileTree.HasPath(p))
			exists, ref, err := r.fileTree.File(p)
			assert.Equal(t, true, exists)
			if assert.NoError(t, err) {
				return
			}
			assert.Equal(t, info, r.metadata[ref.ID()])
		})
	}
}

func Test_handleFileAccessErr(t *testing.T) {
	tests := []struct {
		name                string
		input               error
		expectedPathTracked bool
	}{
		{
			name:                "permission error does not propagate",
			input:               os.ErrPermission,
			expectedPathTracked: true,
		},
		{
			name:                "file does not exist error does not propagate",
			input:               os.ErrNotExist,
			expectedPathTracked: true,
		},
		{
			name:                "non-permission errors are tracked",
			input:               os.ErrInvalid,
			expectedPathTracked: true,
		},
		{
			name:                "non-errors ignored",
			input:               nil,
			expectedPathTracked: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := directoryResolver{
				errPaths: make(map[string]error),
			}
			p := "a/place"
			assert.Equal(t, r.isFileAccessErr(p, test.input), test.expectedPathTracked)
			_, exists := r.errPaths[p]
			assert.Equal(t, test.expectedPathTracked, exists)
		})
	}
}

type indexerMock struct {
	observedRoots   []string
	additionalRoots map[string][]string
}

func (m *indexerMock) indexer(s string, _ *progress.Stage) ([]string, error) {
	m.observedRoots = append(m.observedRoots, s)
	return m.additionalRoots[s], nil
}

func Test_indexAllRoots(t *testing.T) {
	tests := []struct {
		name          string
		root          string
		mock          indexerMock
		expectedRoots []string
	}{
		{
			name: "no additional roots",
			root: "a/place",
			mock: indexerMock{
				additionalRoots: make(map[string][]string),
			},
			expectedRoots: []string{
				"a/place",
			},
		},
		{
			name: "additional roots from a single call",
			root: "a/place",
			mock: indexerMock{
				additionalRoots: map[string][]string{
					"a/place": {
						"another/place",
						"yet-another/place",
					},
				},
			},
			expectedRoots: []string{
				"a/place",
				"another/place",
				"yet-another/place",
			},
		},
		{
			name: "additional roots from a multiple calls",
			root: "a/place",
			mock: indexerMock{
				additionalRoots: map[string][]string{
					"a/place": {
						"another/place",
						"yet-another/place",
					},
					"yet-another/place": {
						"a-quiet-place-2",
						"a-final/place",
					},
				},
			},
			expectedRoots: []string{
				"a/place",
				"another/place",
				"yet-another/place",
				"a-quiet-place-2",
				"a-final/place",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.NoError(t, indexAllRoots(test.root, test.mock.indexer))
		})
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
			resolver, err := newDirectoryResolver(test.fixturePath)
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
	resolver, err := newDirectoryResolver("./test-fixtures/symlinks-simple")
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
	assert.Equal(t, "link_to_new_readme", locations[0].VirtualPath)

	// check that we can access the same file via 2 symlinks
	locations, err = resolver.FilesByPath("./link_to_link_to_new_readme")
	require.NoError(t, err)
	require.Len(t, locations, 1)
	assert.Equal(t, "readme", locations[0].RealPath)
	assert.Equal(t, "link_to_link_to_new_readme", locations[0].VirtualPath)

	// check that we can access the same file via 2 symlinks
	locations, err = resolver.FilesByGlob("**/link_*")
	require.NoError(t, err)
	require.Len(t, locations, 2)

	// returned locations can be in any order
	expectedVirtualPaths := []string{
		"link_to_link_to_new_readme",
		"link_to_new_readme",
	}

	expectedRealPaths := []string{
		"readme",
	}

	actualRealPaths := strset.New()
	actualVirtualPaths := strset.New()
	for _, a := range locations {
		actualVirtualPaths.Add(a.VirtualPath)
		actualRealPaths.Add(a.RealPath)
	}

	assert.ElementsMatch(t, expectedVirtualPaths, actualVirtualPaths.List())
	assert.ElementsMatch(t, expectedRealPaths, actualRealPaths.List())
}

func Test_IndexingNestedSymLinks_ignoredIndexes(t *testing.T) {
	filterFn := func(path string, _ os.FileInfo) bool {
		return strings.HasSuffix(path, string(filepath.Separator)+"readme")
	}

	resolver, err := newDirectoryResolver("./test-fixtures/symlinks-simple", filterFn)
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
	resolver, err := newDirectoryResolver("./test-fixtures/symlinks-multiple-roots/root")
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
	resolver, err := newDirectoryResolver("./test-fixtures/symlinked-root/nested/link-root")
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

	tests := []struct {
		name     string
		location Location
		expects  string
		err      bool
	}{
		{
			name: "use file reference for content requests",
			location: NewLocationFromDirectory("some/place", file.Reference{
				RealPath: file.Path(filepath.Join(cwd, "test-fixtures/image-simple/file-1.txt")),
			}),
			expects: "this file has contents",
		},
		{
			name:     "error on empty file reference",
			location: NewLocationFromDirectory("doesn't matter", file.Reference{}),
			err:      true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r, err := newDirectoryResolver(".")
			require.NoError(t, err)

			actual, err := r.FileContentsByLocation(test.location)
			if test.err {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			if test.expects != "" {
				b, err := ioutil.ReadAll(actual)
				require.NoError(t, err)
				assert.Equal(t, test.expects, string(b))
			}
		})
	}
}

func Test_isUnixSystemRuntimePath(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{
			path:     "proc/place",
			expected: false,
		},
		{
			path:     "/proc/place",
			expected: true,
		},
		{
			path:     "/proc",
			expected: true,
		},
		{
			path:     "/pro/c",
			expected: false,
		},
		{
			path:     "/pro",
			expected: false,
		},
		{
			path:     "/dev",
			expected: true,
		},
		{
			path:     "/sys",
			expected: true,
		},
		{
			path:     "/something/sys",
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			assert.Equal(t, test.expected, isUnixSystemRuntimePath(test.path, nil))
		})
	}
}

func Test_SymlinkLoopWithGlobsShouldResolve(t *testing.T) {
	test := func(t *testing.T) {
		resolver, err := newDirectoryResolver("./test-fixtures/symlinks-loop")
		require.NoError(t, err)

		locations, err := resolver.FilesByGlob("**/file.target")
		require.NoError(t, err)
		// Note: I'm not certain that this behavior is correct, but it is not an infinite loop (which is the point of the test)
		// - block/loop0/file.target
		// - devices/loop0/file.target
		// - devices/loop0/subsystem/loop0/file.target
		assert.Len(t, locations, 3)
	}

	testWithTimeout(t, 5*time.Second, test)
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

func Test_IncludeRootPathInIndex(t *testing.T) {
	filterFn := func(path string, _ os.FileInfo) bool {
		return path != "/"
	}

	resolver, err := newDirectoryResolver("/", filterFn)
	require.NoError(t, err)

	exists, ref, err := resolver.fileTree.File(file.Path("/"))
	require.NoError(t, err)
	require.NotNil(t, ref)
	assert.True(t, exists)

	_, exists = resolver.metadata[ref.ID()]
	require.True(t, exists)
}

func TestDirectoryResolver_indexPath(t *testing.T) {
	// TODO: Ideally we can use an OS abstraction, which would obviate the need for real FS setup.
	tempFile, err := os.CreateTemp("", "")
	require.NoError(t, err)

	resolver, err := newDirectoryResolver(tempFile.Name())
	require.NoError(t, err)

	t.Run("filtering path with nil os.FileInfo", func(t *testing.T) {
		// We use one of these prefixes in order to trigger a pathFilterFn
		filteredPath := unixSystemRuntimePrefixes[0]

		var fileInfo os.FileInfo = nil

		assert.NotPanics(t, func() {
			_, err := resolver.indexPath(filteredPath, fileInfo, nil)
			assert.NoError(t, err)
		})
	})
}
