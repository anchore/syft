package scope

import (
	"testing"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/image"
)

func TestNewScopeFromImageFails(t *testing.T) {
	t.Run("no image given", func(t *testing.T) {
		_, err := NewScopeFromImage(nil, AllLayersScope)
		if err == nil {
			t.Errorf("expected an error condition but none was given")
		}
	})
}

func TestNewScopeFromImageUnknownOption(t *testing.T) {
	img := image.Image{}

	t.Run("unknown option is an error", func(t *testing.T) {
		_, err := NewScopeFromImage(&img, UnknownScope)
		if err == nil {
			t.Errorf("expected an error condition but none was given")
		}
	})
}

func TestNewScopeFromImage(t *testing.T) {
	layer := image.NewLayer(nil)
	img := image.Image{
		Layers: []*image.Layer{layer},
	}

	t.Run("create a new Scope object from image", func(t *testing.T) {
		_, err := NewScopeFromImage(&img, AllLayersScope)
		if err != nil {
			t.Errorf("unexpected error when creating a new Scope from img: %w", err)
		}
	})
}

func TestDirectoryScope(t *testing.T) {
	testCases := []struct {
		desc       string
		input      string
		expString  string
		inputPaths []file.Path
		expRefs    int
	}{
		{
			desc:       "no paths exist",
			input:      "foobar/",
			inputPaths: []file.Path{file.Path("/opt/"), file.Path("/other")},
			expRefs:    0,
		},
		{
			desc:       "path detected",
			input:      "test-fixtures",
			inputPaths: []file.Path{file.Path("path-detected")},
			expRefs:    1,
		},
		{
			desc:       "no files-by-path detected",
			input:      "test-fixtures",
			inputPaths: []file.Path{file.Path("no-path-detected")},
			expRefs:    0,
		},
	}
	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			p, err := NewScopeFromDir(test.input, AllLayersScope)

			if err != nil {
				t.Errorf("could not create NewDirScope: %w", err)
			}
			if p.DirSrc.Path != test.input {
				t.Errorf("mismatched stringer: '%s' != '%s'", p.DirSrc.Path, test.input)
			}

			refs, err := p.FilesByPath(test.inputPaths...)
			if err != nil {
				t.Errorf("FilesByPath call produced an error: %w", err)
			}
			if len(refs) != test.expRefs {
				t.Errorf("unexpected number of refs returned: %d != %d", len(refs), test.expRefs)

			}

		})
	}
}

func TestMultipleFileContentsByRefContents(t *testing.T) {
	testCases := []struct {
		desc     string
		input    string
		path     string
		expected string
	}{
		{
			input:    "test-fixtures/path-detected",
			desc:     "empty file",
			path:     "empty",
			expected: "",
		},
		{
			input:    "test-fixtures/path-detected",
			desc:     "file has contents",
			path:     ".vimrc",
			expected: "\" A .vimrc file\n",
		},
	}
	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			p, err := NewScopeFromDir(test.input, AllLayersScope)
			if err != nil {
				t.Errorf("could not create NewDirScope: %w", err)
			}
			refs, err := p.FilesByPath(file.Path(test.path))
			if err != nil {
				t.Errorf("could not get file references from path: %s, %v", test.path, err)
			}

			if len(refs) != 1 {
				t.Errorf("expected a single ref to be generated but got: %d", len(refs))
			}
			ref := refs[0]

			contents, err := p.MultipleFileContentsByRef(ref)
			content := contents[ref]

			if content != test.expected {
				t.Errorf("unexpected contents from file: '%s' != '%s'", content, test.expected)
			}

		})
	}
}

func TestMultipleFileContentsByRefNoContents(t *testing.T) {
	testCases := []struct {
		desc     string
		input    string
		path     string
		expected string
	}{
		{
			input: "test-fixtures/path-detected",
			desc:  "path does not exist",
			path:  "foo",
		},
	}
	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			p, err := NewScopeFromDir(test.input, AllLayersScope)
			if err != nil {
				t.Errorf("could not create NewDirScope: %w", err)
			}
			refs, err := p.FilesByPath(file.Path(test.path))
			if err != nil {
				t.Errorf("could not get file references from path: %s, %v", test.path, err)
			}

			if len(refs) != 0 {
				t.Errorf("didnt' expect a ref, but got: %d", len(refs))
			}

		})
	}
}

func TestFilesByGlob(t *testing.T) {
	testCases := []struct {
		desc     string
		input    string
		glob     string
		expected int
	}{
		{
			input:    "test-fixtures",
			desc:     "no matches",
			glob:     "bar/foo",
			expected: 0,
		},
		{
			input:    "test-fixtures/path-detected",
			desc:     "a single match",
			glob:     "*vimrc",
			expected: 1,
		},
		{
			input:    "test-fixtures/path-detected",
			desc:     "multiple matches",
			glob:     "*",
			expected: 2,
		},
	}
	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			p, err := NewScopeFromDir(test.input, AllLayersScope)
			if err != nil {
				t.Errorf("could not create NewDirScope: %w", err)
			}

			contents, err := p.FilesByGlob(test.glob)

			if len(contents) != test.expected {
				t.Errorf("unexpected number of files found by glob (%s): %d != %d", test.glob, len(contents), test.expected)
			}

		})
	}
}
