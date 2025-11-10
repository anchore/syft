//go:build !windows
// +build !windows

package file

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-test/deep"
	"github.com/mholt/archives"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func equal(r1, r2 io.Reader) (bool, error) {
	w1 := sha256.New()
	w2 := sha256.New()
	n1, err1 := io.Copy(w1, r1)
	if err1 != nil {
		return false, err1
	}
	n2, err2 := io.Copy(w2, r2)
	if err2 != nil {
		return false, err2
	}

	var b1, b2 [sha256.Size]byte
	copy(b1[:], w1.Sum(nil))
	copy(b2[:], w2.Sum(nil))

	return n1 != n2 || b1 == b2, nil
}

func TestUnzipToDir(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	goldenRootDir := filepath.Join(cwd, "test-fixtures")
	sourceDirPath := path.Join(goldenRootDir, "zip-source")
	archiveFilePath := setupZipFileTest(t, sourceDirPath, false)

	unzipDestinationDir := t.TempDir()

	t.Logf("content path: %s", unzipDestinationDir)

	expectedPaths := len(expectedZipArchiveEntries)
	observedPaths := 0

	err = UnzipToDir(context.Background(), archiveFilePath, unzipDestinationDir)
	if err != nil {
		t.Fatalf("unable to unzip archive: %+v", err)
	}

	// compare the source dir tree and the unzipped tree
	err = filepath.Walk(unzipDestinationDir,
		func(path string, info os.FileInfo, err error) error {
			// We don't unzip the root archive dir, since there's no archive entry for it
			if path != unzipDestinationDir {
				t.Logf("unzipped path: %s", path)
				observedPaths++
			}

			if err != nil {
				t.Fatalf("this should not happen")
				return err
			}

			goldenPath := filepath.Join(sourceDirPath, strings.TrimPrefix(path, unzipDestinationDir))

			if info.IsDir() {
				i, err := os.Stat(goldenPath)
				if err != nil {
					t.Fatalf("unable to stat golden path: %+v", err)
				}
				if !i.IsDir() {
					t.Fatalf("mismatched file types: %s", goldenPath)
				}
				return nil
			}

			// this is a file, not a dir...

			testFile, err := os.Open(path)
			if err != nil {
				t.Fatalf("unable to open test file=%s :%+v", path, err)
			}

			goldenFile, err := os.Open(goldenPath)
			if err != nil {
				t.Fatalf("unable to open golden file=%s :%+v", goldenPath, err)
			}

			same, err := equal(testFile, goldenFile)
			if err != nil {
				t.Fatalf("could not compare files (%s, %s): %+v", goldenPath, path, err)
			}

			if !same {
				t.Errorf("paths are not the same (%s, %s)", goldenPath, path)
			}

			return nil
		})

	if err != nil {
		t.Errorf("failed to walk dir: %+v", err)
	}

	if observedPaths != expectedPaths {
		t.Errorf("missed test paths: %d != %d", observedPaths, expectedPaths)
	}
}

func TestContentsFromZip(t *testing.T) {
	tests := []struct {
		name        string
		archivePrep func(tb testing.TB) string
	}{
		{
			name:        "standard, non-nested zip",
			archivePrep: prepZipSourceFixture,
		},
		{
			name:        "zip with prepended bytes",
			archivePrep: prependZipSourceFixtureWithString(t, "junk at the beginning of the file..."),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			archivePath := test.archivePrep(t)
			expected := zipSourceFixtureExpectedContents()

			var paths []string
			for p := range expected {
				paths = append(paths, p)
			}

			actual, err := ContentsFromZip(context.Background(), archivePath, paths...)
			if err != nil {
				t.Fatalf("unable to extract from unzip archive: %+v", err)
			}

			assertZipSourceFixtureContents(t, actual, expected)
		})
	}
}

func prependZipSourceFixtureWithString(tb testing.TB, value string) func(tb testing.TB) string {
	if len(value) == 0 {
		tb.Fatalf("no bytes given to prefix")
	}
	return func(t testing.TB) string {
		archivePath := prepZipSourceFixture(t)

		// create a temp file
		tmpFile, err := os.CreateTemp(tb.TempDir(), "syft-ziputil-prependZipSourceFixtureWithString-")
		if err != nil {
			t.Fatalf("unable to create tempfile: %+v", err)
		}
		defer tmpFile.Close()

		// write value to the temp file
		if _, err := tmpFile.WriteString(value); err != nil {
			t.Fatalf("unable to write to tempfile: %+v", err)
		}

		// open the original archive
		sourceFile, err := os.Open(archivePath)
		if err != nil {
			t.Fatalf("unable to read source file: %+v", err)
		}

		// copy all contents from the archive to the temp file
		if _, err := io.Copy(tmpFile, sourceFile); err != nil {
			t.Fatalf("unable to copy source to dest: %+v", err)
		}

		sourceFile.Close()

		// remove the original archive and replace it with the temp file
		if err := os.Remove(archivePath); err != nil {
			t.Fatalf("unable to remove original source archive (%q): %+v", archivePath, err)
		}

		if err := os.Rename(tmpFile.Name(), archivePath); err != nil {
			t.Fatalf("unable to move new archive to old path (%q): %+v", tmpFile.Name(), err)
		}

		return archivePath
	}
}

func prepZipSourceFixture(t testing.TB) string {
	t.Helper()
	archivePrefix := path.Join(t.TempDir(), "syft-ziputil-prepZipSourceFixture-")

	// the zip utility will add ".zip" to the end of the given name
	archivePath := archivePrefix + ".zip"

	t.Logf("archive path: %s", archivePath)

	createZipArchive(t, "zip-source", archivePrefix, false)

	return archivePath
}

func zipSourceFixtureExpectedContents() map[string]string {
	return map[string]string{
		filepath.Join("some-dir", "a-file.txt"): "A file! nice!",
		filepath.Join("b-file.txt"):             "B file...",
	}
}

func assertZipSourceFixtureContents(t testing.TB, actual map[string]string, expected map[string]string) {
	t.Helper()
	diffs := deep.Equal(actual, expected)
	if len(diffs) > 0 {
		for _, d := range diffs {
			t.Errorf("diff: %+v", d)
		}

		b, err := json.MarshalIndent(actual, "", "  ")
		if err != nil {
			t.Fatalf("can't show results: %+v", err)
		}

		t.Errorf("full result: %s", string(b))
	}
}

// looks like there isn't a helper for this yet? https://github.com/stretchr/testify/issues/497
func assertErrorAs(expectedErr interface{}) assert.ErrorAssertionFunc {
	return func(t assert.TestingT, actualErr error, i ...interface{}) bool {
		return errors.As(actualErr, &expectedErr)
	}
}

func TestSafeJoin(t *testing.T) {
	tests := []struct {
		prefix       string
		args         []string
		expected     string
		errAssertion assert.ErrorAssertionFunc
	}{
		// go cases...
		{
			prefix: "/a/place",
			args: []string{
				"somewhere/else",
			},
			expected:     "/a/place/somewhere/else",
			errAssertion: assert.NoError,
		},
		{
			prefix: "/a/place",
			args: []string{
				"somewhere/../else",
			},
			expected:     "/a/place/else",
			errAssertion: assert.NoError,
		},
		{
			prefix: "/a/../place",
			args: []string{
				"somewhere/else",
			},
			expected:     "/place/somewhere/else",
			errAssertion: assert.NoError,
		},
		// zip slip examples....
		{
			prefix: "/a/place",
			args: []string{
				"../../../etc/passwd",
			},
			expected:     "",
			errAssertion: assertErrorAs(&errZipSlipDetected{}),
		},
		{
			prefix: "/a/place",
			args: []string{
				"../",
				"../",
			},
			expected:     "",
			errAssertion: assertErrorAs(&errZipSlipDetected{}),
		},
		{
			prefix: "/a/place",
			args: []string{
				"../",
			},
			expected:     "",
			errAssertion: assertErrorAs(&errZipSlipDetected{}),
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%+v:%+v", test.prefix, test.args), func(t *testing.T) {
			actual, err := SafeJoin(test.prefix, test.args...)
			test.errAssertion(t, err)
			assert.Equal(t, test.expected, actual)
		})
	}
}

// TestSymlinkProtection demonstrates that SafeJoin protects against symlink-based
// directory traversal attacks by validating that archive entry paths cannot escape
// the extraction directory.
func TestSymlinkProtection(t *testing.T) {
	tests := []struct {
		name        string
		archivePath string // Path as it would appear in the archive
		expectError bool
		description string
	}{
		{
			name:        "path traversal via ../",
			archivePath: "../../../outside/file.txt",
			expectError: true,
			description: "Archive entry with ../ trying to escape extraction dir",
		},
		{
			name:        "absolute path symlink target",
			archivePath: "../../../sensitive.txt",
			expectError: true,
			description: "Simulates symlink pointing outside via relative path",
		},
		{
			name:        "safe relative path within extraction dir",
			archivePath: "subdir/safe.txt",
			expectError: false,
			description: "Normal file path that stays within extraction directory",
		},
		{
			name:        "safe path with internal ../",
			archivePath: "dir1/../dir2/file.txt",
			expectError: false,
			description: "Path with ../ that still resolves within extraction dir",
		},
		{
			name:        "deeply nested traversal",
			archivePath: "../../../../../../tmp/evil.txt",
			expectError: true,
			description: "Multiple levels of ../ trying to escape",
		},
		{
			name:        "single parent directory escape",
			archivePath: "../",
			expectError: true,
			description: "Simple one-level escape attempt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temp directories to simulate extraction scenario
			tmpDir := t.TempDir()
			extractDir := filepath.Join(tmpDir, "extract")
			outsideDir := filepath.Join(tmpDir, "outside")

			require.NoError(t, os.MkdirAll(extractDir, 0755))
			require.NoError(t, os.MkdirAll(outsideDir, 0755))

			// Create a file outside extraction dir that an attacker might target
			outsideFile := filepath.Join(outsideDir, "sensitive.txt")
			require.NoError(t, os.WriteFile(outsideFile, []byte("sensitive data"), 0644))

			// Test SafeJoin - this is what happens when processing archive entries
			result, err := SafeJoin(extractDir, tt.archivePath)

			if tt.expectError {
				// Should block malicious paths
				require.Error(t, err, "Expected SafeJoin to reject malicious path")
				var zipSlipErr *errZipSlipDetected
				assert.ErrorAs(t, err, &zipSlipErr, "Error should be errZipSlipDetected type")
				assert.Empty(t, result, "Result should be empty for blocked paths")
			} else {
				// Should allow safe paths
				require.NoError(t, err, "Expected SafeJoin to allow safe path")
				assert.NotEmpty(t, result, "Result should not be empty for safe paths")
				assert.True(t, strings.HasPrefix(filepath.Clean(result), filepath.Clean(extractDir)),
					"Safe path should resolve within extraction directory")
			}
		})
	}
}

// TestTarArchivePathTraversalProtection demonstrates that SafeJoin protects against
// tar archives with malicious path traversal attempts (e.g., ../../../etc/passwd).
func TestTarArchivePathTraversalProtection(t *testing.T) {
	// Create a malicious tar archive with path traversal attempts
	tempDir := t.TempDir()
	maliciousArchive := filepath.Join(tempDir, "malicious.tar")

	// Create a temporary directory with a file that we'll add to the archive
	sourceDir := filepath.Join(tempDir, "source")
	require.NoError(t, os.MkdirAll(sourceDir, 0755))

	testFile := filepath.Join(sourceDir, "test.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("malicious content"), 0644))

	// Create a malicious tar manually using Go's archive/tar
	// This allows us to inject path traversal entries
	archiveFile, err := os.Create(maliciousArchive)
	require.NoError(t, err)
	defer archiveFile.Close()

	tw := tar.NewWriter(archiveFile)
	defer tw.Close()

	// Add a file with path traversal in its name
	content := []byte("malicious content")
	header := &tar.Header{
		Name: "../../../tmp/malicious.txt",
		Mode: 0644,
		Size: int64(len(content)),
	}
	require.NoError(t, tw.WriteHeader(header))
	_, err = tw.Write(content)
	require.NoError(t, err)

	require.NoError(t, tw.Close())
	require.NoError(t, archiveFile.Close())

	// Open the archive for extraction
	archive, err := os.Open(maliciousArchive)
	require.NoError(t, err)
	defer archive.Close()

	extractDir := filepath.Join(tempDir, "extract")
	require.NoError(t, os.MkdirAll(extractDir, 0755))

	// Attempt to extract with SafeJoin protection
	visitor := func(_ context.Context, file archives.FileInfo) error {
		destPath, err := SafeJoin(extractDir, file.NameInArchive)
		if err != nil {
			return err
		}

		if file.IsDir() {
			return os.MkdirAll(destPath, file.Mode())
		}

		return nil
	}

	// We expect extraction to fail due to path traversal protection
	err = archives.Tar{}.Extract(context.Background(), archive, visitor)
	require.Error(t, err, "expected error when extracting archive with path traversal")

	// Verify the error is a zip slip detection error
	var zipSlipErr *errZipSlipDetected
	assert.ErrorAs(t, err, &zipSlipErr, "error should be errZipSlipDetected type")
	assert.Contains(t, err.Error(), "path traversal",
		"error should mention path traversal, got: %v", err)
}

// TestTarArchiveLegitimate verifies that legitimate tar archives without path traversal work correctly.
func TestTarArchiveLegitimate(t *testing.T) {
	tempDir := t.TempDir()
	legitimateArchive := filepath.Join(tempDir, "legitimate.tar")

	// Create a legitimate tar archive with safe paths
	archiveFile, err := os.Create(legitimateArchive)
	require.NoError(t, err)
	defer archiveFile.Close()

	tw := tar.NewWriter(archiveFile)
	defer tw.Close()

	// Add files with safe paths
	testFiles := map[string]string{
		"file1.txt":           "content 1",
		"subdir/file2.txt":    "content 2",
		"subdir/nested/file3": "content 3",
	}

	for name, content := range testFiles {
		header := &tar.Header{
			Name: name,
			Mode: 0644,
			Size: int64(len(content)),
		}
		require.NoError(t, tw.WriteHeader(header))
		_, err = tw.Write([]byte(content))
		require.NoError(t, err)
	}

	require.NoError(t, tw.Close())
	require.NoError(t, archiveFile.Close())

	// Open the archive for extraction
	archive, err := os.Open(legitimateArchive)
	require.NoError(t, err)
	defer archive.Close()

	extractDir := filepath.Join(tempDir, "extract")
	require.NoError(t, os.MkdirAll(extractDir, 0755))

	extractedFiles := make(map[string]bool)

	// Extract with SafeJoin protection
	visitor := func(_ context.Context, file archives.FileInfo) error {
		destPath, err := SafeJoin(extractDir, file.NameInArchive)
		if err != nil {
			return err
		}

		extractedFiles[file.NameInArchive] = true

		if file.IsDir() {
			return os.MkdirAll(destPath, file.Mode())
		}

		// Ensure parent directory exists
		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			return err
		}

		// Create the file
		destFile, err := os.Create(destPath)
		if err != nil {
			return err
		}
		defer destFile.Close()

		rc, err := file.Open()
		if err != nil {
			return err
		}
		defer rc.Close()

		_, err = io.Copy(destFile, rc)
		return err
	}

	// Legitimate archive should extract without error
	err = archives.Tar{}.Extract(context.Background(), archive, visitor)
	require.NoError(t, err, "legitimate archive should extract without error")

	// Verify all expected files were extracted
	for name := range testFiles {
		assert.True(t, extractedFiles[name], "file %s should have been extracted", name)

		// Verify the file exists on disk
		extractedPath := filepath.Join(extractDir, name)
		_, err := os.Stat(extractedPath)
		assert.NoError(t, err, "extracted file %s should exist", name)
	}
}
