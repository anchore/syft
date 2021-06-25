package source

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/stereoscope/pkg/image"
)

func TestNewFromImageFails(t *testing.T) {
	t.Run("no image given", func(t *testing.T) {
		_, err := NewFromImage(nil, "")
		if err == nil {
			t.Errorf("expected an error condition but none was given")
		}
	})
}

func TestNewFromImage(t *testing.T) {
	layer := image.NewLayer(nil)
	img := image.Image{
		Layers: []*image.Layer{layer},
	}

	t.Run("create a new source object from image", func(t *testing.T) {
		_, err := NewFromImage(&img, "")
		if err != nil {
			t.Errorf("unexpected error when creating a new Locations from img: %+v", err)
		}
	})
}

func TestNewFromDirectory(t *testing.T) {
	testCases := []struct {
		desc       string
		input      string
		expString  string
		inputPaths []string
		expRefs    int
		expErr     bool
	}{
		{
			desc:       "no paths exist",
			input:      "foobar/",
			inputPaths: []string{"/opt/", "/other"},
			expErr:     true,
		},
		{
			desc:       "path detected",
			input:      "test-fixtures",
			inputPaths: []string{"test-fixtures/path-detected/.vimrc"},
			expRefs:    1,
		},
		{
			desc:       "directory ignored",
			input:      "test-fixtures",
			inputPaths: []string{"test-fixtures/path-detected"},
			expRefs:    0,
		},
		{
			desc:       "no files-by-path detected",
			input:      "test-fixtures",
			inputPaths: []string{"test-fixtures/no-path-detected"},
			expRefs:    0,
		},
	}
	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			src, err := NewFromDirectory(test.input)

			if err != nil {
				t.Errorf("could not create NewDirScope: %+v", err)
			}
			if src.Metadata.Path != test.input {
				t.Errorf("mismatched stringer: '%s' != '%s'", src.Metadata.Path, test.input)
			}
			resolver, err := src.FileResolver(SquashedScope)
			if test.expErr {
				assert.Error(t, err)
				return
			} else {
				assert.NoError(t, err)
			}
			refs, err := resolver.FilesByPath(test.inputPaths...)
			if err != nil {
				t.Errorf("FilesByPath call produced an error: %+v", err)
			}
			if len(refs) != test.expRefs {
				t.Errorf("unexpected number of refs returned: %d != %d", len(refs), test.expRefs)

			}

		})
	}
}

func TestFilesByPathDoesNotExist(t *testing.T) {
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
			src, err := NewFromDirectory(test.input)
			if err != nil {
				t.Errorf("could not create NewDirScope: %+v", err)
			}
			resolver, err := src.FileResolver(SquashedScope)
			if err != nil {
				t.Errorf("could not get resolver error: %+v", err)
			}
			refs, err := resolver.FilesByPath(test.path)
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
			glob:     "**/*vimrc",
			expected: 1,
		},
		{
			input:    "test-fixtures/path-detected",
			desc:     "multiple matches",
			glob:     "**",
			expected: 2,
		},
	}
	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			src, err := NewFromDirectory(test.input)
			if err != nil {
				t.Errorf("could not create NewDirScope: %+v", err)
			}
			resolver, err := src.FileResolver(SquashedScope)
			if err != nil {
				t.Errorf("could not get resolver error: %+v", err)
			}
			contents, err := resolver.FilesByGlob(test.glob)

			if len(contents) != test.expected {
				t.Errorf("unexpected number of files found by glob (%s): %d != %d", test.glob, len(contents), test.expected)
			}

		})
	}
}
