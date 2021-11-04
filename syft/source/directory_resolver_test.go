package source

import (
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/stretchr/testify/assert"
	"github.com/wagoodman/go-progress"
)

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
			input:    "test-fixtures/image-symlinks/file-1.txt",
			expected: "test-fixtures/image-symlinks/file-1.txt",
			refCount: 1,
		},
		{
			name:     "finds a file with relative indirection",
			root:     "./test-fixtures/../test-fixtures",
			input:    "test-fixtures/image-symlinks/file-1.txt",
			expected: "test-fixtures/image-symlinks/file-1.txt",
			refCount: 1,
		},
		{
			// note: this is asserting the old behavior is not supported
			name:     "relative lookup with wrong path fails",
			root:     "./test-fixtures/",
			input:    "image-symlinks/file-1.txt",
			refCount: 0,
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
			expected: "test-fixtures/image-symlinks/file-1.txt",
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
					t.Errorf("expected HasPath() to indicate existance, but did not")
				} else if c.refCount == 0 && hasPath {
					t.Errorf("expeced HasPath() to NOT indicate existance, but does")
				}
			} else if !hasPath {
				t.Errorf("expected HasPath() to indicate existance, but did not (force path)")
			}

			refs, err := resolver.FilesByPath(c.input)
			if err != nil {
				t.Fatalf("could not use resolver: %+v, %+v", err, refs)
			}

			if len(refs) != c.refCount {
				t.Errorf("unexpected number of refs: %d != %d", len(refs), c.refCount)
			}

			for _, actual := range refs {
				if actual.RealPath != c.expected {
					t.Errorf("bad resolve path: '%s'!='%s'", actual.RealPath, c.expected)
				}
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
			input:    []string{"test-fixtures/image-symlinks/file-1.txt", "test-fixtures/image-symlinks/file-2.txt"},
			refCount: 2,
		},
		{
			name:     "skips non-existing files",
			input:    []string{"test-fixtures/image-symlinks/bogus.txt", "test-fixtures/image-symlinks/file-1.txt"},
			refCount: 1,
		},
		{
			name:     "does not return anything for non-existing directories",
			input:    []string{"test-fixtures/non-existing/bogus.txt", "test-fixtures/non-existing/file-1.txt"},
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
	assert.Equal(t, "test-fixtures/image-symlinks/file-1.txt", refs[0].RealPath)
}

func TestDirectoryResolverDoesNotIgnoreRelativeSystemPaths(t *testing.T) {
	// let's make certain that "dev/place" is not ignored, since it is not "/dev/place"
	resolver, err := newDirectoryResolver("test-fixtures/system_paths/target")
	assert.NoError(t, err)
	// ensure the correct filter function is wired up by default
	expectedFn := reflect.ValueOf(isUnixSystemRuntimePath)
	actualFn := reflect.ValueOf(resolver.pathFilterFns[0])
	assert.Equal(t, expectedFn.Pointer(), actualFn.Pointer())

	// all paths should be found (non filtering matches a path)
	refs, err := resolver.FilesByGlob("**/place")
	assert.NoError(t, err)
	// 4: within target/
	// 1: target/link --> relative path to "place"
	// 1: outside_root/link_target/place
	assert.Len(t, refs, 6)

	// ensure that symlink indexing outside of root worked
	ok := false
	test_location := "test-fixtures/system_paths/outside_root/link_target/place"
	for _, actual_loc := range refs {
		if test_location == actual_loc.RealPath {
			ok = true
		}
	}

	if !ok {
		t.Fatalf("could not find test location=%q", test_location)
	}
}

func TestDirectoryResolverUsesPathFilterFunction(t *testing.T) {
	// let's make certain that the index honors the filter function
	filter := func(s string) bool {
		// a dummy function that works for testing purposes
		return strings.Contains(s, "dev/place") || strings.Contains(s, "proc/place") || strings.Contains(s, "sys/place")
	}

	resolver, err := newDirectoryResolver("test-fixtures/system_paths/target", filter)
	assert.NoError(t, err)

	// ensure the correct filter function is wired up by default
	expectedFn := reflect.ValueOf(filter)
	actualFn := reflect.ValueOf(resolver.pathFilterFns[0])
	assert.Equal(t, expectedFn.Pointer(), actualFn.Pointer())
	assert.Len(t, resolver.pathFilterFns, 1)

	refs, err := resolver.FilesByGlob("**/place")
	assert.NoError(t, err)
	// target/home/place + target/link/.../place + outside_root/.../place
	assert.Len(t, refs, 3)
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
			assert.Equal(t, test.expected, isUnixSystemRuntimePath(test.path))
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
			if err != nil {
				t.Fatalf("could not get working dir: %+v", err)
			}

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
		expectedErr         error
		expectedPathTracked bool
	}{
		{
			name:                "permission error does not propagate",
			input:               os.ErrPermission,
			expectedPathTracked: true,
			expectedErr:         nil,
		},
		{
			name:                "file does not exist error does not propagate",
			input:               os.ErrNotExist,
			expectedPathTracked: true,
			expectedErr:         nil,
		},
		{
			name:                "non-permission errors propagate",
			input:               os.ErrInvalid,
			expectedPathTracked: false,
			expectedErr:         os.ErrInvalid,
		},
		{
			name:                "non-errors ignored",
			input:               nil,
			expectedPathTracked: false,
			expectedErr:         nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := directoryResolver{
				errPaths: make(map[string]error),
			}
			p := "a/place"
			assert.ErrorIs(t, r.handleFileAccessErr(p, test.input), test.expectedErr)
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
			expectedPaths: strset.New("test-fixtures/image-simple/file-1.txt", "test-fixtures/image-simple/file-2.txt", "test-fixtures/image-simple/target/really/nested/file-3.txt", "test-fixtures/image-simple/Dockerfile"),
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

func Test_ignoreIrregularFiles(t *testing.T) {
	// NOTE: craeting a pipe/fifo file on demand since git doesn't let me
	// commit one. It is meant to demonstrate that the director resolver
	// will ignore it (and any other irregular file) when indexing a directory
	dir := "./test-fixtures/irregular-files"
	f := "f.fifo"

	err := syscall.Mknod(filepath.Join(dir, f), syscall.S_IFIFO|0666, 0)
	assert.NoError(t, err)
	defer func() {
		err := os.Remove(filepath.Join(dir, f))
		assert.NoError(t, err)
	}()

	fileRefs, err := ioutil.ReadDir(dir)
	assert.NoError(t, err)
	assert.Len(t, fileRefs, 2) // there is an irregular file there

	resolver, err := newDirectoryResolver(dir)
	assert.NoError(t, err)
	assert.Len(t, resolver.fileTree.AllFiles(), 1) // but it won't be indexed :)
}
