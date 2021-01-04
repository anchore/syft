package source

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/afero"
)

func TestNewFromImageFails(t *testing.T) {
	t.Run("no image given", func(t *testing.T) {
		_, err := NewFromImage(nil, AllLayersScope, "")
		if err == nil {
			t.Errorf("expected an error condition but none was given")
		}
	})
}

func TestNewFromImageUnknownOption(t *testing.T) {
	img := image.Image{}

	t.Run("unknown option is an error", func(t *testing.T) {
		_, err := NewFromImage(&img, UnknownScope, "")
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
		_, err := NewFromImage(&img, AllLayersScope, "")
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
	}{
		{
			desc:       "no paths exist",
			input:      "foobar/",
			inputPaths: []string{"/opt/", "/other"},
			expRefs:    0,
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

			refs, err := src.Resolver.FilesByPath(test.inputPaths...)
			if err != nil {
				t.Errorf("FilesByPath call produced an error: %+v", err)
			}
			if len(refs) != test.expRefs {
				t.Errorf("unexpected number of refs returned: %d != %d", len(refs), test.expRefs)

			}

		})
	}
}

func TestMultipleFileContentsByLocation(t *testing.T) {
	testCases := []struct {
		desc     string
		input    string
		path     string
		expected string
	}{
		{
			input:    "test-fixtures/path-detected",
			desc:     "empty file",
			path:     "test-fixtures/path-detected/empty",
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
			p, err := NewFromDirectory(test.input)
			if err != nil {
				t.Errorf("could not create NewDirScope: %+v", err)
			}
			locations, err := p.Resolver.FilesByPath(test.path)
			if err != nil {
				t.Errorf("could not get file references from path: %s, %v", test.path, err)
			}

			if len(locations) != 1 {
				t.Fatalf("expected a single location to be generated but got: %d", len(locations))
			}
			location := locations[0]

			contents, err := p.Resolver.MultipleFileContentsByLocation([]Location{location})
			contentReader := contents[location]

			content, err := ioutil.ReadAll(contentReader)
			if err != nil {
				t.Fatalf("cannot read contents: %+v", err)
			}

			if string(content) != test.expected {
				t.Errorf("unexpected contents from file: '%s' != '%s'", content, test.expected)
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
			p, err := NewFromDirectory(test.input)
			if err != nil {
				t.Errorf("could not create NewDirScope: %+v", err)
			}
			refs, err := p.Resolver.FilesByPath(test.path)
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
			p, err := NewFromDirectory(test.input)
			if err != nil {
				t.Errorf("could not create NewDirScope: %+v", err)
			}

			contents, err := p.Resolver.FilesByGlob(test.glob)

			if len(contents) != test.expected {
				t.Errorf("unexpected number of files found by glob (%s): %d != %d", test.glob, len(contents), test.expected)
			}

		})
	}
}

func TestDetectScheme(t *testing.T) {
	type detectorResult struct {
		src image.Source
		ref string
		err error
	}

	testCases := []struct {
		name             string
		userInput        string
		dirs             []string
		detection        detectorResult
		expectedScheme   Scheme
		expectedLocation string
	}{
		{
			name:      "docker-image-ref",
			userInput: "wagoodman/dive:latest",
			detection: detectorResult{
				src: image.DockerDaemonSource,
				ref: "wagoodman/dive:latest",
			},
			expectedScheme:   ImageScheme,
			expectedLocation: "wagoodman/dive:latest",
		},
		{
			name:      "docker-image-ref-no-tag",
			userInput: "wagoodman/dive",
			detection: detectorResult{
				src: image.DockerDaemonSource,
				ref: "wagoodman/dive",
			},
			expectedScheme:   ImageScheme,
			expectedLocation: "wagoodman/dive",
		},
		{
			name:      "docker-image-explicit-scheme",
			userInput: "docker:wagoodman/dive:latest",
			detection: detectorResult{
				src: image.DockerDaemonSource,
				ref: "wagoodman/dive:latest",
			},
			expectedScheme:   ImageScheme,
			expectedLocation: "wagoodman/dive:latest",
		},
		{
			name:      "docker-image-explicit-scheme-no-tag",
			userInput: "docker:wagoodman/dive",
			detection: detectorResult{
				src: image.DockerDaemonSource,
				ref: "wagoodman/dive",
			},
			expectedScheme:   ImageScheme,
			expectedLocation: "wagoodman/dive",
		},
		{
			name:      "docker-image-edge-case",
			userInput: "docker:latest",
			detection: detectorResult{
				src: image.DockerDaemonSource,
				ref: "latest",
			},
			expectedScheme: ImageScheme,
			// we want to be able to handle this case better, however, I don't see a way to do this
			// the user will need to provide more explicit input (docker:docker:latest)
			expectedLocation: "latest",
		},
		{
			name:      "docker-image-edge-case-explicit",
			userInput: "docker:docker:latest",
			detection: detectorResult{
				src: image.DockerDaemonSource,
				ref: "docker:latest",
			},
			expectedScheme: ImageScheme,
			// we want to be able to handle this case better, however, I don't see a way to do this
			// the user will need to provide more explicit input (docker:docker:latest)
			expectedLocation: "docker:latest",
		},
		{
			name:      "oci-tar",
			userInput: "some/path-to-file",
			detection: detectorResult{
				src: image.OciTarballSource,
				ref: "some/path-to-file",
			},
			expectedScheme:   ImageScheme,
			expectedLocation: "some/path-to-file",
		},
		{
			name:      "oci-dir",
			userInput: "some/path-to-dir",
			detection: detectorResult{
				src: image.OciDirectorySource,
				ref: "some/path-to-dir",
			},
			dirs:             []string{"some/path-to-dir"},
			expectedScheme:   ImageScheme,
			expectedLocation: "some/path-to-dir",
		},
		{
			name:      "guess-dir",
			userInput: "some/path-to-dir",
			detection: detectorResult{
				src: image.UnknownSource,
				ref: "",
			},
			dirs:             []string{"some/path-to-dir"},
			expectedScheme:   DirectoryScheme,
			expectedLocation: "some/path-to-dir",
		},
		{
			name:      "generic-dir-does-not-exist",
			userInput: "some/path-to-dir",
			detection: detectorResult{
				src: image.DockerDaemonSource,
				ref: "some/path-to-dir",
			},
			expectedScheme:   ImageScheme,
			expectedLocation: "some/path-to-dir",
		},
		{
			name:      "explicit-dir",
			userInput: "dir:some/path-to-dir",
			detection: detectorResult{
				src: image.UnknownSource,
				ref: "",
			},
			dirs:             []string{"some/path-to-dir"},
			expectedScheme:   DirectoryScheme,
			expectedLocation: "some/path-to-dir",
		},
		{
			name:      "explicit-current-dir",
			userInput: "dir:.",
			detection: detectorResult{
				src: image.UnknownSource,
				ref: "",
			},
			expectedScheme:   DirectoryScheme,
			expectedLocation: ".",
		},
		{
			name:      "current-dir",
			userInput: ".",
			detection: detectorResult{
				src: image.UnknownSource,
				ref: "",
			},
			expectedScheme:   DirectoryScheme,
			expectedLocation: ".",
		},
		// we should support tilde expansion
		{
			name:      "tilde-expansion-image-implicit",
			userInput: "~/some-path",
			detection: detectorResult{
				src: image.OciDirectorySource,
				ref: "~/some-path",
			},
			expectedScheme:   ImageScheme,
			expectedLocation: "~/some-path",
		},
		{
			name:      "tilde-expansion-dir-implicit",
			userInput: "~/some-path",
			detection: detectorResult{
				src: image.UnknownSource,
				ref: "",
			},
			dirs:             []string{"~/some-path"},
			expectedScheme:   DirectoryScheme,
			expectedLocation: "~/some-path",
		},
		{
			name:             "tilde-expansion-dir-explicit-exists",
			userInput:        "dir:~/some-path",
			dirs:             []string{"~/some-path"},
			expectedScheme:   DirectoryScheme,
			expectedLocation: "~/some-path",
		},
		{
			name:             "tilde-expansion-dir-explicit-dne",
			userInput:        "dir:~/some-path",
			expectedScheme:   DirectoryScheme,
			expectedLocation: "~/some-path",
		},
		{
			name:             "tilde-expansion-dir-implicit-dne",
			userInput:        "~/some-path",
			expectedScheme:   UnknownScheme,
			expectedLocation: "",
		},
	}
	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			fs := afero.NewMemMapFs()

			for _, p := range test.dirs {
				expandedExpectedLocation, err := homedir.Expand(p)
				if err != nil {
					t.Fatalf("unable to expand path=%q: %+v", p, err)
				}
				err = fs.Mkdir(expandedExpectedLocation, os.ModePerm)
				if err != nil {
					t.Fatalf("failed to create dummy tar: %+v", err)
				}
			}

			imageDetector := func(string) (image.Source, string, error) {
				// lean on the users real home directory value
				switch test.detection.src {
				case image.OciDirectorySource, image.DockerTarballSource, image.OciTarballSource:
					expandedExpectedLocation, err := homedir.Expand(test.expectedLocation)
					if err != nil {
						t.Fatalf("unable to expand path=%q: %+v", test.expectedLocation, err)
					}
					return test.detection.src, expandedExpectedLocation, test.detection.err
				default:
					return test.detection.src, test.detection.ref, test.detection.err
				}
			}

			actualScheme, actualLocation, err := detectScheme(fs, imageDetector, test.userInput)
			if err != nil {
				t.Fatalf("unexpected err : %+v", err)
			}

			if actualScheme != test.expectedScheme {
				t.Errorf("expected scheme %q , got %q", test.expectedScheme, actualScheme)
			}

			// lean on the users real home directory value
			expandedExpectedLocation, err := homedir.Expand(test.expectedLocation)
			if err != nil {
				t.Fatalf("unable to expand path=%q: %+v", test.expectedLocation, err)
			}

			if actualLocation != expandedExpectedLocation {
				t.Errorf("expected location %q , got %q", expandedExpectedLocation, actualLocation)
			}
		})
	}
}
