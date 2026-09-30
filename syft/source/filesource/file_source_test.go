package filesource

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
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
	testutil.Chdir(t, "..") // run with source/testdata

	testCases := []struct {
		desc       string
		input      string
		expString  string
		testPathFn func(file.Resolver) ([]file.Location, error)
		expRefs    int
	}{
		{
			desc:  "path detected by glob",
			input: "testdata/file-index-filter/.vimrc",
			testPathFn: func(resolver file.Resolver) ([]file.Location, error) {
				return resolver.FilesByGlob("**/.vimrc", "**/.2", "**/.1/*", "**/empty")
			},
			expRefs: 1,
		},
		{
			desc:  "path detected by abs path",
			input: "testdata/file-index-filter/.vimrc",
			testPathFn: func(resolver file.Resolver) ([]file.Location, error) {
				return resolver.FilesByPath("/.vimrc", "/.2", "/.1/something", "/empty")
			},
			expRefs: 1,
		},
		{
			desc:  "path detected by relative path",
			input: "testdata/file-index-filter/.vimrc",
			testPathFn: func(resolver file.Resolver) ([]file.Location, error) {
				return resolver.FilesByPath(".vimrc", "/.2", "/.1/something", "empty")
			},
			expRefs: 1,
		},
		{
			desc:  "normal path",
			input: "testdata/actual-path/empty",
			testPathFn: func(resolver file.Resolver) ([]file.Location, error) {
				return resolver.FilesByPath("empty")
			},
			expRefs: 1,
		},
		{
			desc:  "path containing symlink",
			input: "testdata/symlink/empty",
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
	if runtime.GOOS == "windows" {
		t.Skip("archive fixtures are generated with a shell script")
	}
	testutil.Chdir(t, "..") // run with source/testdata

	testCases := []struct {
		desc               string
		input              string
		expString          string
		inputPaths         []string
		expRefs            int
		layer2             bool
		contents           string
		skipExtractArchive bool
	}{
		{
			desc:       "path detected",
			input:      "testdata/path-detected",
			inputPaths: []string{"/.vimrc"},
			expRefs:    1,
		},
		{
			desc:       "use first entry for duplicate paths",
			input:      "testdata/path-detected",
			inputPaths: []string{"/.vimrc"},
			expRefs:    1,
			layer2:     true,
			contents:   "Another .vimrc file",
		},
		{
			desc:               "skip extract archive",
			input:              "testdata/path-detected",
			inputPaths:         []string{"/.vimrc"},
			expRefs:            0,
			layer2:             false,
			skipExtractArchive: true,
		},
	}
	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			archivePath := setupArchiveTest(t, test.input, test.layer2)

			cfg := Config{
				Path:               archivePath,
				SkipExtractArchive: test.skipExtractArchive,
			}

			src, err := New(cfg)
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

func TestNewFromFile_RarExtension(t *testing.T) {
	testutil.Chdir(t, "..") // run with source/testdata

	testCases := []struct {
		desc          string
		input         string
		wantExtracted bool
		wantPaths     []string
		wantNoPaths   []string
	}{
		{
			// a Java resource adapter archive is a zip file with a .rar extension: it must not be handed to the RAR
			// extractor, but left for the java cataloger to read as a single file (like a .jar)
			desc:          "zip archive with a .rar name is analyzed as a single file",
			input:         createResourceAdapterArchive(t, t.TempDir()),
			wantExtracted: false,
			wantPaths:     []string{"example-ra-1.0.0.rar"},
			wantNoPaths:   []string{"META-INF/ra.xml", "example-lib-1.0.0.jar"},
		},
		{
			// a self-extracting RAR has an executable stub before the RAR signature. The stub holds no "R" bytes,
			// which is the input that made rardecode v2.2.0 loop forever in its signature search
			desc:          "self-extracting RAR archive is extracted",
			input:         writeSfxRar(t, t.TempDir()),
			wantExtracted: true,
			wantPaths:     []string{"inside.txt"},
			wantNoPaths:   []string{"example-sfx.rar"},
		},
		{
			// a RAR 5.0 archive holding one stored file (inside.txt)
			desc:          "RAR archive is extracted",
			input:         "testdata/rar-archive/example.rar",
			wantExtracted: true,
			wantPaths:     []string{"inside.txt"},
			wantNoPaths:   []string{"example.rar"},
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

			assert.Equal(t, test.wantExtracted, src.(*fileSource).analysisPath != test.input)

			res, err := src.FileResolver(source.SquashedScope)
			require.NoError(t, err)

			for _, p := range test.wantPaths {
				refs, err := res.FilesByPath(p)
				require.NoError(t, err)
				assert.Len(t, refs, 1, "expected to find %q", p)
			}

			for _, p := range test.wantNoPaths {
				refs, err := res.FilesByPath(p)
				require.NoError(t, err)
				assert.Empty(t, refs, "expected not to find %q", p)
			}
		})
	}
}

// createResourceAdapterArchive writes a minimal Java resource adapter archive (a zip file with a .rar extension that
// holds a deployment descriptor and a nested jar) into dir and returns its path.
func createResourceAdapterArchive(t testing.TB, dir string) string {
	t.Helper()

	lib := zipBytes(t, [][2]string{
		{"META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n"},
		{"META-INF/maven/org.example/example-lib/pom.properties", "groupId=org.example\nartifactId=example-lib\nversion=1.0.0\n"},
	})

	ra := zipBytes(t, [][2]string{
		{"META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n"},
		{"META-INF/ra.xml", "<connector/>\n"},
		{"example-lib-1.0.0.jar", string(lib)},
		{"META-INF/maven/org.example/example-ra/pom.properties", "groupId=org.example\nartifactId=example-ra\nversion=1.0.0\n"},
	})

	archivePath := filepath.Join(dir, "example-ra-1.0.0.rar")
	require.NoError(t, os.WriteFile(archivePath, ra, 0o600))
	return archivePath
}

// writeSfxRar writes testdata/rar-archive/example.rar behind a stand-in executable stub into dir and returns its path.
func writeSfxRar(t testing.TB, dir string) string {
	t.Helper()

	rar, err := os.ReadFile("testdata/rar-archive/example.rar")
	require.NoError(t, err)

	sfxPath := filepath.Join(dir, "example-sfx.rar")
	require.NoError(t, os.WriteFile(sfxPath, append(bytes.Repeat([]byte("MZ stub "), 1024), rar...), 0o600))
	return sfxPath
}

// zipBytes returns a zip archive holding the given (name, contents) entries, in order.
func zipBytes(t testing.TB, entries [][2]string) []byte {
	t.Helper()

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, e := range entries {
		f, err := w.Create(e[0])
		require.NoError(t, err)
		_, err = f.Write([]byte(e[1]))
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
	return buf.Bytes()
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
	cmd.Dir = filepath.Join(cwd, "testdata")

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
		cmd.Dir = filepath.Join(cwd, "testdata", path.Base(sourceDirPath+"-2"))
		if err := cmd.Start(); err != nil {
			t.Fatalf("unable to start tar appending fixture script: %+v", err)
		}
		_ = cmd.Wait()
	}
}

func Test_FileSource_ID(t *testing.T) {
	testutil.Chdir(t, "..") // run with source/testdata

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
				Path: "./testdata/does-not-exist",
			},
			wantErr: require.Error,
		},
		{
			name: "to dir",
			cfg: Config{
				Path: "./testdata/image-simple",
			},
			wantErr: require.Error,
		},
		{
			name:       "with path",
			cfg:        Config{Path: "./testdata/image-simple/Dockerfile"},
			want:       artifact.ID("db7146472cf6d49b3ac01b42812fb60020b0b4898b97491b21bb690c808d5159"),
			wantDigest: "sha256:38601c0bb4269a10ce1d00590ea7689c1117dd9274c758653934ab4f2016f80f",
		},
		{
			name: "with path and alias",
			cfg: Config{
				Path: "./testdata/image-simple/Dockerfile",
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
				Path: "testdata/image-simple/Dockerfile",
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
