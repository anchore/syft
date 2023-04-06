//go:build !windows
// +build !windows

package source

import (
	"io"
	"io/fs"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/syft/artifact"
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
			sourceInput, err := ParseInput(test.input, test.platform)
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

func TestSetID(t *testing.T) {
	layer := image.NewLayer(nil)
	layer.Metadata = image.LayerMetadata{
		Digest: "sha256:6f4fb385d4e698647bf2a450749dfbb7bc2831ec9a730ef4046c78c08d468e89",
	}
	img := image.Image{
		Layers: []*image.Layer{layer},
	}

	tests := []struct {
		name     string
		input    *Source
		expected artifact.ID
	}{
		{
			name: "source.SetID sets the ID for FileScheme",
			input: &Source{
				Metadata: Metadata{
					Scheme: FileScheme,
					Path:   "test-fixtures/image-simple/file-1.txt",
				},
			},
			expected: artifact.ID("55096713247489add592ce977637be868497132b36d1e294a3831925ec64319a"),
		},
		{
			name: "source.SetID sets the ID for ImageScheme",
			input: &Source{
				Image: &img,
				Metadata: Metadata{
					Scheme: ImageScheme,
				},
			},
			expected: artifact.ID("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
		},
		{
			name: "source.SetID sets the ID for DirectoryScheme",
			input: &Source{
				Image: &img,
				Metadata: Metadata{
					Scheme: DirectoryScheme,
					Path:   "test-fixtures/image-simple",
				},
			},
			expected: artifact.ID("91db61e5e0ae097ef764796ce85e442a93f2a03e5313d4c7307e9b413f62e8c4"),
		},
		{
			name: "source.SetID sets the ID for UnknownScheme",
			input: &Source{
				Image: &img,
				Metadata: Metadata{
					Scheme: UnknownScheme,
					Path:   "test-fixtures/image-simple",
				},
			},
			expected: artifact.ID("1b0dc351e6577b01"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.input.SetID()
			assert.Equal(t, test.expected, test.input.ID())
		})
	}
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
		layer2     bool
		contents   string
	}{
		{
			desc:       "path detected",
			input:      "test-fixtures/path-detected",
			inputPaths: []string{"/.vimrc"},
			expRefs:    1,
		},
		{
			desc:       "lest entry for duplicate paths",
			input:      "test-fixtures/path-detected",
			inputPaths: []string{"/.vimrc"},
			expRefs:    1,
			layer2:     true,
			contents:   "Another .vimrc file",
		},
	}
	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			archivePath := setupArchiveTest(t, test.input, test.layer2)

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

			if test.contents != "" {
				reader, err := resolver.FileContentsByLocation(refs[0])
				require.NoError(t, err)

				data, err := io.ReadAll(reader)
				require.NoError(t, err)

				assert.Equal(t, test.contents, string(data))
			}

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
		expected   []string
		exclusions []string
		err        bool
	}{
		{
			input:      "test-fixtures/system_paths",
			desc:       "exclude everything",
			glob:       "**",
			expected:   nil,
			exclusions: []string{"**/*"},
		},
		{
			input: "test-fixtures/image-simple",
			desc:  "a single path excluded",
			glob:  "**",
			expected: []string{
				"Dockerfile",
				"file-1.txt",
				"file-2.txt",
			},
			exclusions: []string{"**/target/**"},
		},
		{
			input: "test-fixtures/image-simple",
			desc:  "exclude explicit directory relative to the root",
			glob:  "**",
			expected: []string{
				"Dockerfile",
				"file-1.txt",
				"file-2.txt",
				//"target/really/nested/file-3.txt", // explicitly skipped
			},
			exclusions: []string{"./target"},
		},
		{
			input: "test-fixtures/image-simple",
			desc:  "exclude explicit file relative to the root",
			glob:  "**",
			expected: []string{
				"Dockerfile",
				//"file-1.txt",  // explicitly skipped
				"file-2.txt",
				"target/really/nested/file-3.txt",
			},
			exclusions: []string{"./file-1.txt"},
		},
		{
			input: "test-fixtures/image-simple",
			desc:  "exclude wildcard relative to the root",
			glob:  "**",
			expected: []string{
				"Dockerfile",
				//"file-1.txt",  // explicitly skipped
				//"file-2.txt", // explicitly skipped
				"target/really/nested/file-3.txt",
			},
			exclusions: []string{"./*.txt"},
		},
		{
			input: "test-fixtures/image-simple",
			desc:  "exclude files deeper",
			glob:  "**",
			expected: []string{
				"Dockerfile",
				"file-1.txt",
				"file-2.txt",
				//"target/really/nested/file-3.txt", // explicitly skipped
			},
			exclusions: []string{"**/really/**"},
		},
		{
			input: "test-fixtures/image-simple",
			desc:  "files excluded with extension",
			glob:  "**",
			expected: []string{
				"Dockerfile",
				//"file-1.txt",  // explicitly skipped
				//"file-2.txt", // explicitly skipped
				//"target/really/nested/file-3.txt", // explicitly skipped
			},
			exclusions: []string{"**/*.txt"},
		},
		{
			input: "test-fixtures/image-simple",
			desc:  "keep files with different extensions",
			glob:  "**",
			expected: []string{
				"Dockerfile",
				"file-1.txt",
				"file-2.txt",
				"target/really/nested/file-3.txt",
			},
			exclusions: []string{"**/target/**/*.jar"},
		},
		{
			input: "test-fixtures/path-detected",
			desc:  "file directly excluded",
			glob:  "**",
			expected: []string{
				".vimrc",
			},
			exclusions: []string{"**/empty"},
		},
		{
			input: "test-fixtures/path-detected",
			desc:  "pattern error containing **/",
			glob:  "**",
			expected: []string{
				".vimrc",
			},
			exclusions: []string{"/**/empty"},
			err:        true,
		},
		{
			input: "test-fixtures/path-detected",
			desc:  "pattern error incorrect start",
			glob:  "**",
			expected: []string{
				".vimrc",
			},
			exclusions: []string{"empty"},
			err:        true,
		},
		{
			input: "test-fixtures/path-detected",
			desc:  "pattern error starting with /",
			glob:  "**",
			expected: []string{
				".vimrc",
			},
			exclusions: []string{"/empty"},
			err:        true,
		},
	}
	registryOpts := &image.RegistryOptions{}
	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			sourceInput, err := ParseInput("dir:"+test.input, "")
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
			locations, err := resolver.FilesByGlob(test.glob)
			if err != nil {
				t.Errorf("could not get files by glob: %s+v", err)
			}
			var actual []string
			for _, l := range locations {
				actual = append(actual, l.RealPath)
			}

			sort.Strings(test.expected)
			sort.Strings(actual)

			assert.Equal(t, test.expected, actual, "diff \n"+cmp.Diff(test.expected, actual))
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
			sourceInput, err := ParseInput(archiveLocation, "")
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

type dummyInfo struct {
	isDir bool
}

func (d dummyInfo) Name() string {
	//TODO implement me
	panic("implement me")
}

func (d dummyInfo) Size() int64 {
	//TODO implement me
	panic("implement me")
}

func (d dummyInfo) Mode() fs.FileMode {
	//TODO implement me
	panic("implement me")
}

func (d dummyInfo) ModTime() time.Time {
	//TODO implement me
	panic("implement me")
}

func (d dummyInfo) IsDir() bool {
	return d.isDir
}

func (d dummyInfo) Sys() any {
	//TODO implement me
	panic("implement me")
}

func Test_crossPlatformExclusions(t *testing.T) {
	testCases := []struct {
		desc     string
		root     string
		path     string
		finfo    os.FileInfo
		exclude  string
		walkHint error
	}{
		{
			desc:     "directory exclusion",
			root:     "/",
			path:     "/usr/var/lib",
			exclude:  "**/var/lib",
			finfo:    dummyInfo{isDir: true},
			walkHint: fs.SkipDir,
		},
		{
			desc:     "no file info",
			root:     "/",
			path:     "/usr/var/lib",
			exclude:  "**/var/lib",
			walkHint: errSkipPath,
		},
		// linux specific tests...
		{
			desc:     "linux doublestar",
			root:     "/usr",
			path:     "/usr/var/lib/etc.txt",
			exclude:  "**/*.txt",
			finfo:    dummyInfo{isDir: false},
			walkHint: errSkipPath,
		},
		{
			desc:    "linux relative",
			root:    "/usr/var/lib",
			path:    "/usr/var/lib/etc.txt",
			exclude: "./*.txt",
			finfo:   dummyInfo{isDir: false},

			walkHint: errSkipPath,
		},
		{
			desc:     "linux one level",
			root:     "/usr",
			path:     "/usr/var/lib/etc.txt",
			exclude:  "*/*.txt",
			finfo:    dummyInfo{isDir: false},
			walkHint: nil,
		},
		// NOTE: since these tests will run in linux and macOS, the windows paths will be
		// considered relative if they do not start with a forward slash and paths with backslashes
		// won't be modified by the filepath.ToSlash call, so these are emulating the result of
		// filepath.ToSlash usage

		// windows specific tests...
		{
			desc:     "windows doublestar",
			root:     "/C:/User/stuff",
			path:     "/C:/User/stuff/thing.txt",
			exclude:  "**/*.txt",
			finfo:    dummyInfo{isDir: false},
			walkHint: errSkipPath,
		},
		{
			desc:     "windows relative",
			root:     "/C:/User/stuff",
			path:     "/C:/User/stuff/thing.txt",
			exclude:  "./*.txt",
			finfo:    dummyInfo{isDir: false},
			walkHint: errSkipPath,
		},
		{
			desc:     "windows one level",
			root:     "/C:/User/stuff",
			path:     "/C:/User/stuff/thing.txt",
			exclude:  "*/*.txt",
			finfo:    dummyInfo{isDir: false},
			walkHint: nil,
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			fns, err := getDirectoryExclusionFunctions(test.root, []string{test.exclude})
			require.NoError(t, err)

			for _, f := range fns {
				result := f(test.path, test.finfo, nil)
				require.Equal(t, test.walkHint, result)
			}
		})
	}
}

// createArchive creates a new archive file at destinationArchivePath based on the directory found at sourceDirPath.
func createArchive(t testing.TB, sourceDirPath, destinationArchivePath string, layer2 bool) {
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

	if layer2 {
		cmd = exec.Command("tar", "-rvf", destinationArchivePath, ".")
		cmd.Dir = filepath.Join(cwd, "test-fixtures", path.Base(sourceDirPath+"-2"))
		if err := cmd.Start(); err != nil {
			t.Fatalf("unable to start tar appending fixture script: %+v", err)
		}
		_ = cmd.Wait()
	}
}

// setupArchiveTest encapsulates common test setup work for tar file tests. It returns a cleanup function,
// which should be called (typically deferred) by the caller, the path of the created tar archive, and an error,
// which should trigger a fatal test failure in the consuming test. The returned cleanup function will never be nil
// (even if there's an error), and it should always be called.
func setupArchiveTest(t testing.TB, sourceDirPath string, layer2 bool) string {
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
	createArchive(t, sourceDirPath, destinationArchiveFilePath, layer2)

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
