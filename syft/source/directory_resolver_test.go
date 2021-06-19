package source

import (
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
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
	expectedFn := reflect.ValueOf(isSystemRuntimePath)
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
	assert.Contains(t, refs, Location{
		RealPath: "test-fixtures/system_paths/outside_root/link_target/place",
	})
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

func TestIsSystemRuntimePath(t *testing.T) {
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
			assert.Equal(t, test.expected, isSystemRuntimePath(test.path))
		})
	}

}
