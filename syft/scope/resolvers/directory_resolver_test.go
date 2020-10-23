package resolvers

import (
	"testing"

	"github.com/anchore/stereoscope/pkg/file"
)

func TestDirectoryResolver_FilesByPath(t *testing.T) {
	cases := []struct {
		name     string
		root     string
		input    string
		expected string
		refCount int
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
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resolver := DirectoryResolver{c.root}
			refs, err := resolver.FilesByPath(file.Path(c.input))
			if err != nil {
				t.Fatalf("could not use resolver: %+v, %+v", err, refs)
			}

			if len(refs) != c.refCount {
				t.Errorf("unexpected number of refs: %d != %d", len(refs), c.refCount)
			}

			for _, actual := range refs {
				if actual.Path != file.Path(c.expected) {
					t.Errorf("bad resolve path: '%s'!='%s'", actual.Path, c.expected)
				}
			}
		})
	}
}

func TestDirectoryResolver_MultipleFilesByPath(t *testing.T) {
	cases := []struct {
		name     string
		input    []file.Path
		refCount int
	}{
		{
			name:     "finds multiple files",
			input:    []file.Path{file.Path("test-fixtures/image-symlinks/file-1.txt"), file.Path("test-fixtures/image-symlinks/file-2.txt")},
			refCount: 2,
		},
		{
			name:     "skips non-existing files",
			input:    []file.Path{file.Path("test-fixtures/image-symlinks/bogus.txt"), file.Path("test-fixtures/image-symlinks/file-1.txt")},
			refCount: 1,
		},
		{
			name:     "does not return anything for non-existing directories",
			input:    []file.Path{file.Path("test-fixtures/non-existing/bogus.txt"), file.Path("test-fixtures/non-existing/file-1.txt")},
			refCount: 0,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resolver := DirectoryResolver{"test-fixtures"}

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

func TestDirectoryResolver_MultipleFileContentsByRef(t *testing.T) {
	cases := []struct {
		name     string
		input    []file.Path
		refCount int
		contents []string
	}{
		{
			name:     "gets multiple file contents",
			input:    []file.Path{file.Path("test-fixtures/image-symlinks/file-1.txt"), file.Path("test-fixtures/image-symlinks/file-2.txt")},
			refCount: 2,
		},
		{
			name:     "skips non-existing files",
			input:    []file.Path{file.Path("test-fixtures/image-symlinks/bogus.txt"), file.Path("test-fixtures/image-symlinks/file-1.txt")},
			refCount: 1,
		},
		{
			name:     "does not return anything for non-existing directories",
			input:    []file.Path{file.Path("test-fixtures/non-existing/bogus.txt"), file.Path("test-fixtures/non-existing/file-1.txt")},
			refCount: 0,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			refs := make([]file.Reference, 0)
			resolver := DirectoryResolver{"test-fixtures"}

			for _, p := range c.input {
				newRefs, err := resolver.FilesByPath(p)
				if err != nil {
					t.Errorf("could not generate refs: %+v", err)
				}
				for _, ref := range newRefs {
					refs = append(refs, ref)
				}
			}

			contents, err := resolver.MultipleFileContentsByRef(refs...)
			if err != nil {
				t.Fatalf("unable to generate file contents by ref: %+v", err)
			}
			if len(contents) != c.refCount {
				t.Errorf("unexpected number of refs produced: %d != %d", len(contents), c.refCount)
			}

		})
	}
}

func TestDirectoryResolver_FilesByGlobMultiple(t *testing.T) {
	t.Run("finds multiple matching files", func(t *testing.T) {
		resolver := DirectoryResolver{"test-fixtures"}
		refs, err := resolver.FilesByGlob("image-symlinks/file*")

		if err != nil {
			t.Fatalf("could not use resolver: %+v, %+v", err, refs)
		}

		if len(refs) != 2 {
			t.Errorf("unexpected number of refs: %d != 2", len(refs))
		}

	})
}

func TestDirectoryResolver_FilesByGlobRecursive(t *testing.T) {
	t.Run("finds multiple matching files", func(t *testing.T) {
		resolver := DirectoryResolver{"test-fixtures"}
		refs, err := resolver.FilesByGlob("**/*.txt")

		if err != nil {
			t.Fatalf("could not use resolver: %+v, %+v", err, refs)
		}

		if len(refs) != 4 {
			t.Errorf("unexpected number of refs: %d != 4", len(refs))
		}

	})
}

func TestDirectoryResolver_FilesByGlobSingle(t *testing.T) {
	t.Run("finds multiple matching files", func(t *testing.T) {
		resolver := DirectoryResolver{"test-fixtures"}
		refs, err := resolver.FilesByGlob("image-symlinks/*1.txt")
		if err != nil {
			t.Fatalf("could not use resolver: %+v, %+v", err, refs)
		}

		if len(refs) != 1 {
			t.Errorf("unexpected number of refs: %d != 1", len(refs))
		}

	})
}
