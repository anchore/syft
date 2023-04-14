//go:build !windows
// +build !windows

package source

import (
	"io"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/stereoscope/pkg/file"
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
			resolver, err := newDirectoryResolver(c.relativeRoot, "")
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

			resolver, err := newDirectoryResolver(absRoot, "")
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
			resolver, err := newDirectoryResolver(c.root, "")
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
			resolver, err := newDirectoryResolver("./test-fixtures", "")
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
	resolver, err := newDirectoryResolver("./test-fixtures", "")
	assert.NoError(t, err)
	refs, err := resolver.FilesByGlob("**/image-symlinks/file*")
	assert.NoError(t, err)

	assert.Len(t, refs, 2)
}

func TestDirectoryResolver_FilesByGlobRecursive(t *testing.T) {
	resolver, err := newDirectoryResolver("./test-fixtures/image-symlinks", "")
	assert.NoError(t, err)
	refs, err := resolver.FilesByGlob("**/*.txt")
	assert.NoError(t, err)
	assert.Len(t, refs, 6)
}

func TestDirectoryResolver_FilesByGlobSingle(t *testing.T) {
	resolver, err := newDirectoryResolver("./test-fixtures", "")
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
			resolver, err := newDirectoryResolver("./test-fixtures/symlinks-simple", "")
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
	resolver, err := newDirectoryResolver("test-fixtures/system_paths/target", "")
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
			expected: errSkipPath,
		},
		{
			name: "named pipe",
			info: testFileInfo{
				mode: os.ModeNamedPipe,
			},
			expected: errSkipPath,
		},
		{
			name: "char device",
			info: testFileInfo{
				mode: os.ModeCharDevice,
			},
			expected: errSkipPath,
		},
		{
			name: "block device",
			info: testFileInfo{
				mode: os.ModeDevice,
			},
			expected: errSkipPath,
		},
		{
			name: "irregular",
			info: testFileInfo{
				mode: os.ModeIrregular,
			},
			expected: errSkipPath,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, disallowByFileType("dont/care", test.info, nil))
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
			resolver, err := newDirectoryResolver(test.fixturePath, "")
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
	resolver, err := newDirectoryResolver("./test-fixtures/symlinks-simple", "")
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
	require.Len(t, locations, 1) // you would think this is 2, however, they point to the same file, and glob only returns unique files

	// returned locations can be in any order
	expectedVirtualPaths := []string{
		"link_to_link_to_new_readme",
		//"link_to_new_readme", // we filter out this one because the first symlink resolves to the same file
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
	filterFn := func(path string, _ os.FileInfo, _ error) error {
		if strings.HasSuffix(path, string(filepath.Separator)+"readme") {
			return errSkipPath
		}
		return nil
	}

	resolver, err := newDirectoryResolver("./test-fixtures/symlinks-simple", "", filterFn)
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
	resolver, err := newDirectoryResolver("./test-fixtures/symlinks-multiple-roots/root", "")
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
	resolver, err := newDirectoryResolver("./test-fixtures/symlinked-root/nested/link-root", "")
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

	r, err := newDirectoryResolver(".", "")
	require.NoError(t, err)

	exists, existingPath, err := r.tree.File(file.Path(filepath.Join(cwd, "test-fixtures/image-simple/file-1.txt")))
	require.True(t, exists)
	require.NoError(t, err)
	require.True(t, existingPath.HasReference())

	tests := []struct {
		name     string
		location Location
		expects  string
		err      bool
	}{
		{
			name:     "use file reference for content requests",
			location: NewLocationFromDirectory("some/place", *existingPath.Reference),
			expects:  "this file has contents",
		},
		{
			name:     "error on empty file reference",
			location: NewLocationFromDirectory("doesn't matter", file.Reference{}),
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
		expected error
	}{
		{
			path: "proc/place",
		},
		{
			path:     "/proc/place",
			expected: fs.SkipDir,
		},
		{
			path:     "/proc",
			expected: fs.SkipDir,
		},
		{
			path: "/pro/c",
		},
		{
			path: "/pro",
		},
		{
			path:     "/dev",
			expected: fs.SkipDir,
		},
		{
			path:     "/sys",
			expected: fs.SkipDir,
		},
		{
			path: "/something/sys",
		},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			assert.Equal(t, test.expected, disallowUnixSystemRuntimePath(test.path, nil, nil))
		})
	}
}

func Test_SymlinkLoopWithGlobsShouldResolve(t *testing.T) {
	test := func(t *testing.T) {
		resolver, err := newDirectoryResolver("./test-fixtures/symlinks-loop", "")
		require.NoError(t, err)

		locations, err := resolver.FilesByGlob("**/file.target")
		require.NoError(t, err)

		require.Len(t, locations, 1)
		assert.Equal(t, "devices/loop0/file.target", locations[0].RealPath)
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
			resolver, err := newDirectoryResolver(c.root, c.root)
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
		runner   func(FileResolver) []Location
		expected []Location
	}{
		{
			name: "by mimetype",
			runner: func(resolver FileResolver) []Location {
				// links should not show up when searching mimetype
				actualLocations, err := resolver.FilesByMIMEType("text/plain")
				assert.NoError(t, err)
				return actualLocations
			},
			expected: []Location{
				NewLocation("file-1.txt"),        // note: missing virtual path "file-1.txt"
				NewLocation("file-3.txt"),        // note: missing virtual path "file-3.txt"
				NewLocation("file-2.txt"),        // note: missing virtual path "file-2.txt"
				NewLocation("parent/file-4.txt"), // note: missing virtual path "file-4.txt"
			},
		},
		{
			name: "by glob to links",
			runner: func(resolver FileResolver) []Location {
				// links are searched, but resolve to the real files
				// for that reason we need to place **/ in front (which is not the same for other resolvers)
				actualLocations, err := resolver.FilesByGlob("**/*ink-*")
				assert.NoError(t, err)
				return actualLocations
			},
			expected: []Location{
				NewVirtualLocation("file-1.txt", "link-1"),
				NewVirtualLocation("file-2.txt", "link-2"),
				// we already have this real file path via another link, so only one is returned
				//NewVirtualLocation("file-2.txt", "link-indirect"),
				NewVirtualLocation("file-3.txt", "link-within"),
			},
		},
		{
			name: "by basename",
			runner: func(resolver FileResolver) []Location {
				// links are searched, but resolve to the real files
				actualLocations, err := resolver.FilesByGlob("**/file-2.txt")
				assert.NoError(t, err)
				return actualLocations
			},
			expected: []Location{
				// this has two copies in the base image, which overwrites the same location
				NewLocation("file-2.txt"), // note: missing virtual path "file-2.txt",
			},
		},
		{
			name: "by basename glob",
			runner: func(resolver FileResolver) []Location {
				// links are searched, but resolve to the real files
				actualLocations, err := resolver.FilesByGlob("**/file-?.txt")
				assert.NoError(t, err)
				return actualLocations
			},
			expected: []Location{
				NewLocation("file-1.txt"),        // note: missing virtual path "file-1.txt"
				NewLocation("file-2.txt"),        // note: missing virtual path "file-2.txt"
				NewLocation("file-3.txt"),        // note: missing virtual path "file-3.txt"
				NewLocation("parent/file-4.txt"), // note: missing virtual path "parent/file-4.txt"
			},
		},
		{
			name: "by basename glob to links",
			runner: func(resolver FileResolver) []Location {
				actualLocations, err := resolver.FilesByGlob("**/link-*")
				assert.NoError(t, err)
				return actualLocations
			},
			expected: []Location{
				{
					LocationData: LocationData{
						Coordinates: Coordinates{
							RealPath: "file-1.txt",
						},
						VirtualPath: "link-1",
						ref:         file.Reference{RealPath: "file-1.txt"},
					},
				},
				{
					LocationData: LocationData{
						Coordinates: Coordinates{
							RealPath: "file-2.txt",
						},
						VirtualPath: "link-2",
						ref:         file.Reference{RealPath: "file-2.txt"},
					},
				},
				// we already have this real file path via another link, so only one is returned
				//{
				//  LocationData: LocationData{
				//	  Coordinates: Coordinates{
				//  		RealPath: "file-2.txt",
				//  	},
				//  	VirtualPath: "link-indirect",
				//  	ref:         file.Reference{RealPath: "file-2.txt"},
				//  },
				//},
				{
					LocationData: LocationData{
						Coordinates: Coordinates{
							RealPath: "file-3.txt",
						},
						VirtualPath: "link-within",
						ref:         file.Reference{RealPath: "file-3.txt"},
					},
				},
			},
		},
		{
			name: "by extension",
			runner: func(resolver FileResolver) []Location {
				// links are searched, but resolve to the real files
				actualLocations, err := resolver.FilesByGlob("**/*.txt")
				assert.NoError(t, err)
				return actualLocations
			},
			expected: []Location{
				NewLocation("file-1.txt"),        // note: missing virtual path "file-1.txt"
				NewLocation("file-2.txt"),        // note: missing virtual path "file-2.txt"
				NewLocation("file-3.txt"),        // note: missing virtual path "file-3.txt"
				NewLocation("parent/file-4.txt"), // note: missing virtual path "parent/file-4.txt"
			},
		},
		{
			name: "by path to degree 1 link",
			runner: func(resolver FileResolver) []Location {
				// links resolve to the final file
				actualLocations, err := resolver.FilesByPath("/link-2")
				assert.NoError(t, err)
				return actualLocations
			},
			expected: []Location{
				// we have multiple copies across layers
				NewVirtualLocation("file-2.txt", "link-2"),
			},
		},
		{
			name: "by path to degree 2 link",
			runner: func(resolver FileResolver) []Location {
				// multiple links resolves to the final file
				actualLocations, err := resolver.FilesByPath("/link-indirect")
				assert.NoError(t, err)
				return actualLocations
			},
			expected: []Location{
				// we have multiple copies across layers
				NewVirtualLocation("file-2.txt", "link-indirect"),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver, err := newDirectoryResolver("./test-fixtures/symlinks-from-image-symlinks-fixture", "")
			require.NoError(t, err)
			assert.NoError(t, err)

			actual := test.runner(resolver)

			compareLocations(t, test.expected, actual)
		})
	}
}

func TestDirectoryResolver_DoNotAddVirtualPathsToTree(t *testing.T) {
	resolver, err := newDirectoryResolver("./test-fixtures/symlinks-prune-indexing", "")
	require.NoError(t, err)

	var allRealPaths []file.Path
	for l := range resolver.AllLocations() {
		allRealPaths = append(allRealPaths, file.Path(l.RealPath))
	}
	pathSet := file.NewPathSet(allRealPaths...)

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
	resolver, err := newDirectoryResolver("./test-fixtures/system_paths", "")
	assert.NoError(t, err)

	var dirLoc *Location
	for loc := range resolver.AllLocations() {
		entry, err := resolver.index.Get(loc.ref)
		require.NoError(t, err)
		if entry.Metadata.IsDir {
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
	resolver, err := newDirectoryResolver("./test-fixtures/symlinks-from-image-symlinks-fixture", "")
	assert.NoError(t, err)

	paths := strset.New()
	for loc := range resolver.AllLocations() {
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
