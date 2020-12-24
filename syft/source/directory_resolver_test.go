package source

import (
	"testing"
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
		{
			name:     "directories ignored",
			root:     "./test-fixtures/",
			input:    "/image-symlinks",
			refCount: 0,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resolver := DirectoryResolver{c.root}
			refs, err := resolver.FilesByPath(c.input)
			if err != nil {
				t.Fatalf("could not use resolver: %+v, %+v", err, refs)
			}

			if len(refs) != c.refCount {
				t.Errorf("unexpected number of refs: %d != %d", len(refs), c.refCount)
			}

			for _, actual := range refs {
				if actual.Path != c.expected {
					t.Errorf("bad resolve path: '%s'!='%s'", actual.Path, c.expected)
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
		input    []string
		refCount int
		contents []string
	}{
		{
			name:     "gets multiple file contents",
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
			locations := make([]Location, 0)
			resolver := DirectoryResolver{"test-fixtures"}

			for _, p := range c.input {
				newRefs, err := resolver.FilesByPath(p)
				if err != nil {
					t.Errorf("could not generate locations: %+v", err)
				}
				for _, ref := range newRefs {
					locations = append(locations, ref)
				}
			}

			contents, err := resolver.MultipleFileContentsByLocation(locations)
			if err != nil {
				t.Fatalf("unable to generate file contents by ref: %+v", err)
			}
			if len(contents) != c.refCount {
				t.Errorf("unexpected number of locations produced: %d != %d", len(contents), c.refCount)
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

		expected := 2
		if len(refs) != expected {
			t.Errorf("unexpected number of refs: %d != %d", len(refs), expected)
		}

	})
}

func TestDirectoryResolver_FilesByGlobRecursive(t *testing.T) {
	t.Run("finds multiple matching files", func(t *testing.T) {
		resolver := DirectoryResolver{"test-fixtures/image-symlinks"}
		refs, err := resolver.FilesByGlob("**/*.txt")

		if err != nil {
			t.Fatalf("could not use resolver: %+v, %+v", err, refs)
		}

		expected := 6
		if len(refs) != expected {
			t.Errorf("unexpected number of refs: %d != %d", len(refs), expected)
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

		expected := 1
		if len(refs) != expected {
			t.Errorf("unexpected number of refs: %d != %d", len(refs), expected)
		}

	})
}
