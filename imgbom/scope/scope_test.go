package scope

import (
	"testing"

	"github.com/anchore/stereoscope/pkg/file"
)

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
			p, err := NewDirScope(test.input, AllLayersScope)

			if err != nil {
				t.Errorf("could not create NewDirScope: %w", err)
			}
			if p.dirSrc.Path != test.input {
				t.Errorf("mismatched stringer: '%s' != '%s'", p.dirSrc.Path, test.input)
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

func TestMultipleFileContentsByRef(t *testing.T) {
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
			desc:     "path does not exist",
			path:     "foo",
			expected: "",
		},
		{
			input:    "test-fixtures/path-detected",
			desc:     "file has contents",
			path:     "test-fixtures/path-detected/.vimrc",
			expected: "\" A .vimrc file\n",
		},
	}
	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			p, err := NewDirScope(test.input, AllLayersScope)
			if err != nil {
				t.Errorf("could not create NewDirScope: %w", err)
			}
			ref := file.NewFileReference(file.Path(test.path))
			contents, err := p.MultipleFileContentsByRef(ref)
			content := contents[ref]

			if content != test.expected {
				t.Errorf("unexpected contents from file: '%s' != '%s'", content, test.expected)
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
			p, err := NewDirScope(test.input, AllLayersScope)
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
