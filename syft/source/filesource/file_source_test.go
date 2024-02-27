package filesource

import (
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/testutil"
	"github.com/anchore/syft/syft/source"
)

func TestNewFromFile(t *testing.T) {
	testutil.Chdir(t, "..") // run with source/test-fixtures

	testCases := []struct {
		desc       string
		input      string
		expString  string
		testPathFn func(file.Resolver) ([]file.Location, error)
		expRefs    int
	}{
		{
			desc:  "path detected by glob",
			input: "test-fixtures/file-index-filter/.vimrc",
			testPathFn: func(resolver file.Resolver) ([]file.Location, error) {
				return resolver.FilesByGlob("**/.vimrc", "**/.2", "**/.1/*", "**/empty")
			},
			expRefs: 1,
		},
		{
			desc:  "path detected by abs path",
			input: "test-fixtures/file-index-filter/.vimrc",
			testPathFn: func(resolver file.Resolver) ([]file.Location, error) {
				return resolver.FilesByPath("/.vimrc", "/.2", "/.1/something", "/empty")
			},
			expRefs: 1,
		},
		{
			desc:  "path detected by relative path",
			input: "test-fixtures/file-index-filter/.vimrc",
			testPathFn: func(resolver file.Resolver) ([]file.Location, error) {
				return resolver.FilesByPath(".vimrc", "/.2", "/.1/something", "empty")
			},
			expRefs: 1,
		},
		{
			desc:  "normal path",
			input: "test-fixtures/actual-path/empty",
			testPathFn: func(resolver file.Resolver) ([]file.Location, error) {
				return resolver.FilesByPath("empty")
			},
			expRefs: 1,
		},
		{
			desc:  "path containing symlink",
			input: "test-fixtures/symlink/empty",
			testPathFn: func(resolver file.Resolver) ([]file.Location, error) {
				return resolver.FilesByPath("empty")
			},
			expRefs: 1,
		},
	}
	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			src, err := New(Config{
				Path: test.input,
			})
			require.NoError(t, err)
			t.Cleanup(func() {
				require.NoError(t, src.Close())
			})

			assert.Equal(t, test.input, src.Describe().Metadata.(source.FileMetadata).Path)

			res, err := src.FileResolver(source.SquashedScope)
			require.NoError(t, err)

			refs, err := test.testPathFn(res)
			require.NoError(t, err)
			require.Len(t, refs, test.expRefs)
			if test.expRefs == 1 {
				assert.Equal(t, path.Base(test.input), path.Base(refs[0].RealPath))
			}

		})
	}
}

func TestNewFromFile_WithArchive(t *testing.T) {
	testutil.Chdir(t, "..") // run with source/test-fixtures

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
			desc:       "use first entry for duplicate paths",
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

			src, err := New(Config{
				Path: archivePath,
			})
			require.NoError(t, err)
			t.Cleanup(func() {
				require.NoError(t, src.Close())
			})

			assert.Equal(t, archivePath, src.Describe().Metadata.(source.FileMetadata).Path)

			res, err := src.FileResolver(source.SquashedScope)
			require.NoError(t, err)

			refs, err := res.FilesByPath(test.inputPaths...)
			require.NoError(t, err)
			assert.Len(t, refs, test.expRefs)

			if test.contents != "" {
				reader, err := res.FileContentsByLocation(refs[0])
				require.NoError(t, err)

				data, err := io.ReadAll(reader)
				require.NoError(t, err)

				assert.Equal(t, test.contents, string(data))
			}

		})
	}
}

// setupArchiveTest encapsulates common test setup work for tar file tests. It returns a cleanup function,
// which should be called (typically deferred) by the caller, the path of the created tar archive, and an error,
// which should trigger a fatal test failure in the consuming test. The returned cleanup function will never be nil
// (even if there's an error), and it should always be called.
func setupArchiveTest(t testing.TB, sourceDirPath string, layer2 bool) string {
	t.Helper()

	archivePrefix, err := os.CreateTemp("", "syft-archive-TEST-")
	require.NoError(t, err)

	t.Cleanup(func() {
		assert.NoError(t, os.Remove(archivePrefix.Name()))
	})

	destinationArchiveFilePath := archivePrefix.Name() + ".tar"
	t.Logf("archive path: %s", destinationArchiveFilePath)
	createArchive(t, sourceDirPath, destinationArchiveFilePath, layer2)

	t.Cleanup(func() {
		assert.NoError(t, os.Remove(destinationArchiveFilePath))
	})

	cwd, err := os.Getwd()
	require.NoError(t, err)

	t.Logf("running from: %s", cwd)

	return destinationArchiveFilePath
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

func Test_FileSource_ID(t *testing.T) {
	testutil.Chdir(t, "..") // run with source/test-fixtures

	tests := []struct {
		name       string
		cfg        Config
		want       artifact.ID
		wantDigest string
		wantErr    require.ErrorAssertionFunc
	}{
		{
			name:    "empty",
			cfg:     Config{},
			wantErr: require.Error,
		},
		{
			name: "does not exist",
			cfg: Config{
				Path: "./test-fixtures/does-not-exist",
			},
			wantErr: require.Error,
		},
		{
			name: "to dir",
			cfg: Config{
				Path: "./test-fixtures/image-simple",
			},
			wantErr: require.Error,
		},
		{
			name:       "with path",
			cfg:        Config{Path: "./test-fixtures/image-simple/Dockerfile"},
			want:       artifact.ID("db7146472cf6d49b3ac01b42812fb60020b0b4898b97491b21bb690c808d5159"),
			wantDigest: "sha256:38601c0bb4269a10ce1d00590ea7689c1117dd9274c758653934ab4f2016f80f",
		},
		{
			name: "with path and alias",
			cfg: Config{
				Path: "./test-fixtures/image-simple/Dockerfile",
				Alias: source.Alias{
					Name:    "name-me-that!",
					Version: "version-me-this!",
				},
			},
			want:       artifact.ID("3c713003305ac6605255cec8bf4ea649aa44b2b9a9f3a07bd683869d1363438a"),
			wantDigest: "sha256:38601c0bb4269a10ce1d00590ea7689c1117dd9274c758653934ab4f2016f80f",
		},
		{
			name: "other fields do not affect ID",
			cfg: Config{
				Path: "test-fixtures/image-simple/Dockerfile",
				Exclude: source.ExcludeConfig{
					Paths: []string{"a", "b"},
				},
			},
			want:       artifact.ID("db7146472cf6d49b3ac01b42812fb60020b0b4898b97491b21bb690c808d5159"),
			wantDigest: "sha256:38601c0bb4269a10ce1d00590ea7689c1117dd9274c758653934ab4f2016f80f",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}
			newSource, err := New(tt.cfg)
			tt.wantErr(t, err)
			if err != nil {
				return
			}
			s := newSource.(*fileSource)
			assert.Equalf(t, tt.want, s.ID(), "ID() mismatch")
			assert.Equalf(t, tt.wantDigest, s.digestForVersion, "digestForVersion mismatch")
		})
	}
}
