package source

import (
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"

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
	}{
		{
			desc:       "no paths exist",
			input:      "foobar/",
			inputPaths: []string{"/opt/", "/other"},
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
			assert.NoError(t, err)

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
			inputPaths: []string{"test-fixtures/path-detected/.vimrc"},
			expRefs:    1,
		},
		{
			desc:       "directory ignored",
			input:      "test-fixtures",
			notExist:   "foobar/",
			inputPaths: []string{"test-fixtures/path-detected"},
			expRefs:    0,
		},
		{
			desc:       "no files-by-path detected",
			input:      "test-fixtures",
			notExist:   "foobar/",
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

			if len(contents) != test.expected {
				t.Errorf("unexpected number of files found by glob (%s): %d != %d", test.glob, len(contents), test.expected)
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
