package source

import (
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
			resolver := newDirectoryResolver(c.root)

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
			resolver := newDirectoryResolver("./test-fixtures")

			refs, err := resolver.FilesByPath(c.input...)
			if err != nil {
				t.Fatalf("could not use resolver: %+v, %+v", err, refs)
			}

			if len(refs) != c.refCount {
				t.Errorf("unexpected number of refs: %d != %d", len(refs), c.refCount)
			}
		})
	}
}

func TestDirectoryResolver_FilesByGlobMultiple(t *testing.T) {
	t.Run("finds multiple matching files", func(t *testing.T) {
		resolver := newDirectoryResolver("./test-fixtures")
		refs, err := resolver.FilesByGlob("**/image-symlinks/file*")

		if err != nil {
			t.Fatalf("could not use resolver: %+v, %+v", err, refs)
		}

		assert.Len(t, refs, 2)

	})
}

func TestDirectoryResolver_FilesByGlobRecursive(t *testing.T) {
	t.Run("finds multiple matching files", func(t *testing.T) {
		resolver := newDirectoryResolver("./test-fixtures/image-symlinks")
		refs, err := resolver.FilesByGlob("**/*.txt")

		if err != nil {
			t.Fatalf("could not use resolver: %+v, %+v", err, refs)
		}

		assert.Len(t, refs, 6)

	})
}

func TestDirectoryResolver_FilesByGlobSingle(t *testing.T) {
	t.Run("finds multiple matching files", func(t *testing.T) {
		resolver := newDirectoryResolver("./test-fixtures")
		refs, err := resolver.FilesByGlob("**/image-symlinks/*1.txt")
		if err != nil {
			t.Fatalf("could not use resolver: %+v, %+v", err, refs)
		}

		assert.Len(t, refs, 1)
		assert.Equal(t, "test-fixtures/image-symlinks/file-1.txt", refs[0].RealPath)

	})
}
