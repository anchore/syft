//go:build !windows
// +build !windows

package source

import (
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/anchore/stereoscope/pkg/imagetest"

	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/stereoscope/pkg/image"
)

func TestParseInput(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		platform string
		expected Scheme
		errFn    require.ErrorAssertionFunc
	}{
		{
			name:     "ParseInput parses a file input",
			input:    "test-fixtures/image-simple/file-1.txt",
			expected: FileScheme,
		},
		{
			name:     "errors out when using platform for non-image scheme",
			input:    "test-fixtures/image-simple/file-1.txt",
			platform: "arm64",
			errFn:    require.Error,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.errFn == nil {
				test.errFn = require.NoError
			}
			sourceInput, err := ParseInput(test.input, test.platform, true)
			test.errFn(t, err)
			if test.expected != "" {
				require.NotNil(t, sourceInput)
				assert.Equal(t, sourceInput.Scheme, test.expected)
			}
		})
	}
}

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
		desc         string
		input        string
		expString    string
		inputPaths   []string
		expectedRefs int
		expectedErr  bool
	}{
		{
			desc:        "no paths exist",
			input:       "foobar/",
			inputPaths:  []string{"/opt/", "/other"},
			expectedErr: true,
		},
		{
			desc:         "path detected",
			input:        "test-fixtures",
			inputPaths:   []string{"path-detected/.vimrc"},
			expectedRefs: 1,
		},
		{
			desc:         "directory ignored",
			input:        "test-fixtures",
			inputPaths:   []string{"path-detected"},
			expectedRefs: 0,
		},
		{
			desc:         "no files-by-path detected",
			input:        "test-fixtures",
			inputPaths:   []string{"no-path-detected"},
			expectedRefs: 0,
		},
	}
	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			src, err := NewFromDirectory(test.input)
			require.NoError(t, err)
			assert.Equal(t, test.input, src.Metadata.Path)

			resolver, err := src.FileResolver(SquashedScope)
			if test.expectedErr {
				if err == nil {
					t.Fatal("expected an error when making the resolver but got none")
				}
				return
			} else {
				require.NoError(t, err)
			}

			refs, err := resolver.FilesByPath(test.inputPaths...)
			if err != nil {
				t.Errorf("FilesByPath call produced an error: %+v", err)
			}
			if len(refs) != test.expectedRefs {
				t.Errorf("unexpected number of refs returned: %d != %d", len(refs), test.expectedRefs)

			}

		})
	}
}

func TestNewFromFile(t *testing.T) {
	testCases := []struct {
		desc       string
		input      string
		expString  string
		inputPaths []string
		expRefs    int
	}{
		{
			desc:       "path detected",
			input:      "test-fixtures/path-detected",
			inputPaths: []string{"/.vimrc"},
			expRefs:    1,
		},
	}
	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			src, cleanup := NewFromFile(test.input)
			if cleanup != nil {
				t.Cleanup(cleanup)
			}

			assert.Equal(t, test.input, src.Metadata.Path)
			assert.Equal(t, src.Metadata.Path, src.path)

			resolver, err := src.FileResolver(SquashedScope)
			require.NoError(t, err)

			refs, err := resolver.FilesByPath(test.inputPaths...)
			require.NoError(t, err)
			assert.Len(t, refs, test.expRefs)

		})
	}
}

func TestNewFromFile_WithArchive(t *testing.T) {
	testCases := []struct {
		desc       string
		input      string
		expString  string
		inputPaths []string
		expRefs    int
	}{
		{
			desc:       "path detected",
			input:      "test-fixtures/path-detected",
			inputPaths: []string{"/.vimrc"},
			expRefs:    1,
		},
	}
	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			archivePath := setupArchiveTest(t, test.input)

			src, cleanup := NewFromFile(archivePath)
			if cleanup != nil {
				t.Cleanup(cleanup)
			}

			assert.Equal(t, archivePath, src.Metadata.Path)
			assert.NotEqual(t, src.Metadata.Path, src.path)

			resolver, err := src.FileResolver(SquashedScope)
			require.NoError(t, err)

			refs, err := resolver.FilesByPath(test.inputPaths...)
			require.NoError(t, err)
			assert.Len(t, refs, test.expRefs)

		})
	}
}

func TestNewFromDirectoryShared(t *testing.T) {
	testCases := []struct {
		desc       string
		input      string
		expString  string
		notExist   string
		inputPaths []string
		expRefs    int
	}{
		{
			desc:       "path detected",
			input:      "test-fixtures",
			notExist:   "foobar/",
			inputPaths: []string{"path-detected/.vimrc"},
			expRefs:    1,
		},
		{
			desc:       "directory ignored",
			input:      "test-fixtures",
			notExist:   "foobar/",
			inputPaths: []string{"path-detected"},
			expRefs:    0,
		},
		{
			desc:       "no files-by-path detected",
			input:      "test-fixtures",
			notExist:   "foobar/",
			inputPaths: []string{"no-path-detected"},
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

			_, err = src.FileResolver(SquashedScope)
			assert.NoError(t, err)

			src.Metadata.Path = test.notExist
			resolver2, err := src.FileResolver(SquashedScope)
			assert.NoError(t, err)

			refs, err := resolver2.FilesByPath(test.inputPaths...)
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
			if err != nil {
				t.Errorf("could not get files by glob: %s+v", err)
			}
			if len(contents) != test.expected {
				t.Errorf("unexpected number of files found by glob (%s): %d != %d", test.glob, len(contents), test.expected)
			}

		})
	}
}

func TestDirectoryExclusions(t *testing.T) {
	testCases := []struct {
		desc       string
		input      string
		glob       string
		expected   int
		exclusions []string
		err        bool
	}{
		{
			input:      "test-fixtures/system_paths",
			desc:       "exclude everything",
			glob:       "**",
			expected:   0,
			exclusions: []string{"**/*"},
		},
		{
			input:      "test-fixtures/image-simple",
			desc:       "a single path excluded",
			glob:       "**",
			expected:   3,
			exclusions: []string{"**/target/**"},
		},
		{
			input:      "test-fixtures/image-simple",
			desc:       "exclude explicit directory relative to the root",
			glob:       "**",
			expected:   3,
			exclusions: []string{"./target"},
		},
		{
			input:      "test-fixtures/image-simple",
			desc:       "exclude explicit file relative to the root",
			glob:       "**",
			expected:   3,
			exclusions: []string{"./file-1.txt"},
		},
		{
			input:      "test-fixtures/image-simple",
			desc:       "exclude wildcard relative to the root",
			glob:       "**",
			expected:   2,
			exclusions: []string{"./*.txt"},
		},
		{
			input:      "test-fixtures/image-simple",
			desc:       "exclude files deeper",
			glob:       "**",
			expected:   3,
			exclusions: []string{"**/really/**"},
		},
		{
			input:      "test-fixtures/image-simple",
			desc:       "files excluded with extension",
			glob:       "**",
			expected:   1,
			exclusions: []string{"**/*.txt"},
		},
		{
			input:      "test-fixtures/image-simple",
			desc:       "keep files with different extensions",
			glob:       "**",
			expected:   4,
			exclusions: []string{"**/target/**/*.jar"},
		},
		{
			input:      "test-fixtures/path-detected",
			desc:       "file directly excluded",
			glob:       "**",
			expected:   1,
			exclusions: []string{"**/empty"},
		},
		{
			input:      "test-fixtures/path-detected",
			desc:       "pattern error containing **/",
			glob:       "**",
			expected:   1,
			exclusions: []string{"/**/empty"},
			err:        true,
		},
		{
			input:      "test-fixtures/path-detected",
			desc:       "pattern error incorrect start",
			glob:       "**",
			expected:   1,
			exclusions: []string{"empty"},
			err:        true,
		},
		{
			input:      "test-fixtures/path-detected",
			desc:       "pattern error starting with /",
			glob:       "**",
			expected:   1,
			exclusions: []string{"/empty"},
			err:        true,
		},
	}
	registryOpts := &image.RegistryOptions{}
	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			sourceInput, err := ParseInput("dir:"+test.input, "", false)
			require.NoError(t, err)
			src, fn, err := New(*sourceInput, registryOpts, test.exclusions)
			defer fn()

			if test.err {
				_, err = src.FileResolver(SquashedScope)
				if err == nil {
					t.Errorf("expected an error for patterns: %s", strings.Join(test.exclusions, " or "))
				}
				return
			}

			if err != nil {
				t.Errorf("could not create NewDirScope: %+v", err)
			}
			resolver, err := src.FileResolver(SquashedScope)
			if err != nil {
				t.Errorf("could not get resolver error: %+v", err)
			}
			contents, err := resolver.FilesByGlob(test.glob)
			if err != nil {
				t.Errorf("could not get files by glob: %s+v", err)
			}
			if len(contents) != test.expected {
				t.Errorf("wrong number of files after exclusions (%s): %d != %d", test.glob, len(contents), test.expected)
			}
		})
	}
}

func TestImageExclusions(t *testing.T) {
	testCases := []struct {
		desc       string
		input      string
		glob       string
		expected   int
		exclusions []string
	}{
		// NOTE: in the Dockerfile, /target is moved to /, which makes /really a top-level dir
		{
			input:      "image-simple",
			desc:       "a single path excluded",
			glob:       "**",
			expected:   2,
			exclusions: []string{"/really/**"},
		},
		{
			input:      "image-simple",
			desc:       "a directly referenced directory is excluded",
			glob:       "**",
			expected:   2,
			exclusions: []string{"/really"},
		},
		{
			input:      "image-simple",
			desc:       "a partial directory is not excluded",
			glob:       "**",
			expected:   3,
			exclusions: []string{"/reall"},
		},
		{
			input:      "image-simple",
			desc:       "exclude files deeper",
			glob:       "**",
			expected:   2,
			exclusions: []string{"**/nested/**"},
		},
		{
			input:      "image-simple",
			desc:       "files excluded with extension",
			glob:       "**",
			expected:   2,
			exclusions: []string{"**/*1.txt"},
		},
		{
			input:      "image-simple",
			desc:       "keep files with different extensions",
			glob:       "**",
			expected:   3,
			exclusions: []string{"**/target/**/*.jar"},
		},
		{
			input:      "image-simple",
			desc:       "file directly excluded",
			glob:       "**",
			expected:   2,
			exclusions: []string{"**/somefile-1.txt"}, // file-1 renamed to somefile-1 in Dockerfile
		},
	}
	registryOpts := &image.RegistryOptions{}
	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			archiveLocation := imagetest.PrepareFixtureImage(t, "docker-archive", test.input)
			sourceInput, err := ParseInput(archiveLocation, "", false)
			require.NoError(t, err)
			src, fn, err := New(*sourceInput, registryOpts, test.exclusions)
			defer fn()

			if err != nil {
				t.Errorf("could not create NewDirScope: %+v", err)
			}
			resolver, err := src.FileResolver(SquashedScope)
			if err != nil {
				t.Errorf("could not get resolver error: %+v", err)
			}
			contents, err := resolver.FilesByGlob(test.glob)
			if err != nil {
				t.Errorf("could not get files by glob: %s+v", err)
			}
			if len(contents) != test.expected {
				t.Errorf("wrong number of files after exclusions (%s): %d != %d", test.glob, len(contents), test.expected)
			}
		})
	}
}

// createArchive creates a new archive file at destinationArchivePath based on the directory found at sourceDirPath.
func createArchive(t testing.TB, sourceDirPath, destinationArchivePath string) {
	t.Helper()

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("unable to get cwd: %+v", err)
	}

	cmd := exec.Command("./generate-tar-fixture-from-source-dir.sh", destinationArchivePath, path.Base(sourceDirPath))
	cmd.Dir = filepath.Join(cwd, "test-fixtures")

	if err := cmd.Start(); err != nil {
		t.Fatalf("unable to start generate zip fixture script: %+v", err)
	}

	if err := cmd.Wait(); err != nil {
		if exiterr, ok := err.(*exec.ExitError); ok {
			// The program has exited with an exit code != 0

			// This works on both Unix and Windows. Although package
			// syscall is generally platform dependent, WaitStatus is
			// defined for both Unix and Windows and in both cases has
			// an ExitStatus() method with the same signature.
			if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
				if status.ExitStatus() != 0 {
					t.Fatalf("failed to generate fixture: rc=%d", status.ExitStatus())
				}
			}
		} else {
			t.Fatalf("unable to get generate fixture script result: %+v", err)
		}
	}

}

// setupArchiveTest encapsulates common test setup work for tar file tests. It returns a cleanup function,
// which should be called (typically deferred) by the caller, the path of the created tar archive, and an error,
// which should trigger a fatal test failure in the consuming test. The returned cleanup function will never be nil
// (even if there's an error), and it should always be called.
func setupArchiveTest(t testing.TB, sourceDirPath string) string {
	t.Helper()

	archivePrefix, err := ioutil.TempFile("", "syft-archive-TEST-")
	require.NoError(t, err)

	t.Cleanup(
		assertNoError(t,
			func() error {
				return os.Remove(archivePrefix.Name())
			},
		),
	)

	destinationArchiveFilePath := archivePrefix.Name() + ".tar"
	t.Logf("archive path: %s", destinationArchiveFilePath)
	createArchive(t, sourceDirPath, destinationArchiveFilePath)

	t.Cleanup(
		assertNoError(t,
			func() error {
				return os.Remove(destinationArchiveFilePath)
			},
		),
	)

	cwd, err := os.Getwd()
	require.NoError(t, err)

	t.Logf("running from: %s", cwd)

	return destinationArchiveFilePath
}

func assertNoError(t testing.TB, fn func() error) func() {
	return func() {
		assert.NoError(t, fn())
	}
}
