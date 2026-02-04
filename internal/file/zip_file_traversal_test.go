//go:build !windows
// +build !windows

package file

import (
	"archive/zip"
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

// TestSafeJoin_SymlinkProtection demonstrates that SafeJoin protects against
// directory traversal attacks by validating that archive entry paths cannot escape
// the extraction directory.
func TestSafeJoin_SymlinkProtection(t *testing.T) {
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

// TestUnzipToDir_SymlinkAttacks tests UnzipToDir function with malicious ZIP archives
// containing symlink entries that attempt path traversal attacks.
//
// EXPECTED BEHAVIOR: UnzipToDir should either:
//  1. Detect and reject symlinks explicitly with a security error, OR
//  2. Extract them safely (library converts symlinks to regular files)
func TestUnzipToDir_SymlinkAttacks(t *testing.T) {
	tests := []struct {
		name        string
		symlinkName string
		fileName    string
		errContains string
	}{
		{
			name:        "direct symlink to outside directory",
			symlinkName: "evil_link",
			fileName:    "evil_link/payload.txt",
			errContains: "not a directory", // attempt to write through symlink leaf (which is not a directory)
		},
		{
			name:        "directory symlink attack",
			symlinkName: "safe_dir/link",
			fileName:    "safe_dir/link/payload.txt",
			errContains: "not a directory", // attempt to write through symlink (which is not a directory)
		},
		{
			name:        "symlink without payload file",
			symlinkName: "standalone_link",
			fileName:    "", // no payload file
			errContains: "", // no error expected, symlink without payload is safe
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()

			// create outside target directory
			outsideDir := filepath.Join(tempDir, "outside_target")
			require.NoError(t, os.MkdirAll(outsideDir, 0755))

			// create extraction directory
			extractDir := filepath.Join(tempDir, "extract")
			require.NoError(t, os.MkdirAll(extractDir, 0755))

			maliciousZip := createMaliciousZipWithSymlink(t, tempDir, tt.symlinkName, outsideDir, tt.fileName)

			err := UnzipToDir(context.Background(), maliciousZip, extractDir)

			// check error expectations
			if tt.errContains != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errContains)
			} else {
				require.NoError(t, err)
			}

			analyzeExtractionDirectory(t, extractDir)

			// check if payload file escaped extraction directory
			if tt.fileName != "" {
				maliciousFile := filepath.Join(outsideDir, filepath.Base(tt.fileName))
				checkFileOutsideExtraction(t, maliciousFile)
			}

			// check if symlink was created pointing outside
			symlinkPath := filepath.Join(extractDir, tt.symlinkName)
			checkSymlinkCreation(t, symlinkPath, extractDir, outsideDir)
		})
	}
}

// TestContentsFromZip_SymlinkAttacks tests the ContentsFromZip function with malicious
// ZIP archives containing symlink entries.
//
// EXPECTED BEHAVIOR: ContentsFromZip should either:
//  1. Reject symlinks explicitly, OR
//  2. Return empty content for symlinks (library behavior)
//
// Though ContentsFromZip doesn't write to disk, but if symlinks are followed, it could read sensitive
// files from outside the archive.
func TestContentsFromZip_SymlinkAttacks(t *testing.T) {
	tests := []struct {
		name          string
		symlinkName   string
		symlinkTarget string
		requestPath   string
		errContains   string
	}{
		{
			name:          "request symlink entry directly",
			symlinkName:   "evil_link",
			symlinkTarget: "/etc/hosts", // attempt to read sensitive file
			requestPath:   "evil_link",
			errContains:   "", // no error expected - library returns symlink metadata
		},
		{
			name:          "symlink in nested directory",
			symlinkName:   "nested/link",
			symlinkTarget: "/etc/hosts",
			requestPath:   "nested/link",
			errContains:   "", // no error expected - library returns symlink metadata
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()

			// create malicious ZIP with symlink entry (no payload file needed)
			maliciousZip := createMaliciousZipWithSymlink(t, tempDir, tt.symlinkName, tt.symlinkTarget, "")

			contents, err := ContentsFromZip(context.Background(), maliciousZip, tt.requestPath)

			// check error expectations
			if tt.errContains != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errContains)
				return
			}
			require.NoError(t, err)

			// verify symlink handling - library should return symlink target as content (metadata)
			content, found := contents[tt.requestPath]
			require.True(t, found, "symlink entry should be found in results")

			// verify symlink was NOT followed (content should be target path or empty)
			if content != "" && content != tt.symlinkTarget {
				// content is not empty and not the symlink target - check if actual file was read
				if _, statErr := os.Stat(tt.symlinkTarget); statErr == nil {
					targetContent, readErr := os.ReadFile(tt.symlinkTarget)
					if readErr == nil && string(targetContent) == content {
						t.Errorf("critical issue!... symlink was FOLLOWED and external file content was read!")
						t.Logf("  symlink: %s → %s", tt.requestPath, tt.symlinkTarget)
						t.Logf("  content length: %d bytes", len(content))
					}
				}
			}
		})
	}
}

// TestExtractFromZipToUniqueTempFile_SymlinkAttacks tests the ExtractFromZipToUniqueTempFile
// function with malicious ZIP archives containing symlink entries.
//
// EXPECTED BEHAVIOR: ExtractFromZipToUniqueTempFile should either:
//  1. Reject symlinks explicitly, OR
//  2. Extract them safely (library converts to empty files, filepath.Base sanitizes names)
//
// This function uses filepath.Base() on the archive entry name for temp file prefix and
// os.CreateTemp() which creates files in the specified directory, so it should be protected.
func TestExtractFromZipToUniqueTempFile_SymlinkAttacks(t *testing.T) {
	tests := []struct {
		name          string
		symlinkName   string
		symlinkTarget string
		requestPath   string
		errContains   string
	}{
		{
			name:          "extract symlink entry to temp file",
			symlinkName:   "evil_link",
			symlinkTarget: "/etc/passwd",
			requestPath:   "evil_link",
			errContains:   "", // no error expected - library extracts symlink metadata
		},
		{
			name:          "extract nested symlink",
			symlinkName:   "nested/dir/link",
			symlinkTarget: "/tmp/outside",
			requestPath:   "nested/dir/link",
			errContains:   "", // no error expected
		},
		{
			name:          "extract path traversal symlink name",
			symlinkName:   "../../escape",
			symlinkTarget: "/tmp/outside",
			requestPath:   "../../escape",
			errContains:   "", // no error expected - filepath.Base sanitizes name
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()

			maliciousZip := createMaliciousZipWithSymlink(t, tempDir, tt.symlinkName, tt.symlinkTarget, "")

			// create temp directory for extraction
			extractTempDir := filepath.Join(tempDir, "temp_extract")
			require.NoError(t, os.MkdirAll(extractTempDir, 0755))

			openers, err := ExtractFromZipToUniqueTempFile(context.Background(), maliciousZip, extractTempDir, tt.requestPath)

			// check error expectations
			if tt.errContains != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errContains)
				return
			}
			require.NoError(t, err)

			// verify symlink was extracted
			opener, found := openers[tt.requestPath]
			require.True(t, found, "symlink entry should be extracted")

			// verify temp file is within temp directory
			tempFilePath := opener.path
			cleanTempDir := filepath.Clean(extractTempDir)
			cleanTempFile := filepath.Clean(tempFilePath)
			require.True(t, strings.HasPrefix(cleanTempFile, cleanTempDir),
				"temp file must be within temp directory: %s not in %s", cleanTempFile, cleanTempDir)

			// verify symlink was NOT followed (content should be target path or empty)
			f, openErr := opener.Open()
			require.NoError(t, openErr)
			defer f.Close()

			content, readErr := io.ReadAll(f)
			require.NoError(t, readErr)

			// check if symlink was followed (content matches actual file)
			if len(content) > 0 && string(content) != tt.symlinkTarget {
				if _, statErr := os.Stat(tt.symlinkTarget); statErr == nil {
					targetContent, readErr := os.ReadFile(tt.symlinkTarget)
					if readErr == nil && string(targetContent) == string(content) {
						t.Errorf("critical issue!... symlink was FOLLOWED and external file content was copied!")
						t.Logf("  symlink: %s → %s", tt.requestPath, tt.symlinkTarget)
						t.Logf("  content length: %d bytes", len(content))
					}
				}
			}
		})
	}
}

// forensicFindings contains the results of analyzing an extraction directory
type forensicFindings struct {
	symlinksFound          []forensicSymlink
	regularFiles           []string
	directories            []string
	symlinkVulnerabilities []string
}

type forensicSymlink struct {
	path              string
	target            string
	escapesExtraction bool
	resolvedPath      string
}

// analyzeExtractionDirectory walks the extraction directory and detects symlinks that point
// outside the extraction directory. It is silent unless vulnerabilities are found.
func analyzeExtractionDirectory(t *testing.T, extractDir string) forensicFindings {
	t.Helper()

	findings := forensicFindings{}

	filepath.Walk(extractDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// only log if there's an error walking the directory
			t.Logf("Error walking %s: %v", path, err)
			return nil
		}

		relPath := strings.TrimPrefix(path, extractDir+"/")
		if relPath == "" {
			relPath = "."
		}

		// use Lstat to detect symlinks without following them
		linfo, lerr := os.Lstat(path)
		if lerr == nil && linfo.Mode()&os.ModeSymlink != 0 {
			target, _ := os.Readlink(path)

			// resolve to see where it actually points
			var resolvedPath string
			var escapesExtraction bool

			if filepath.IsAbs(target) {
				// absolute symlink
				resolvedPath = target
				cleanExtractDir := filepath.Clean(extractDir)
				escapesExtraction = !strings.HasPrefix(filepath.Clean(target), cleanExtractDir)

				if escapesExtraction {
					t.Errorf("critical issue!... absolute symlink created: %s → %s", relPath, target)
					t.Logf("  this symlink points outside the extraction directory")
					findings.symlinkVulnerabilities = append(findings.symlinkVulnerabilities,
						fmt.Sprintf("absolute symlink: %s → %s", relPath, target))
				}
			} else {
				// relative symlink - resolve it
				resolvedPath = filepath.Join(filepath.Dir(path), target)
				cleanResolved := filepath.Clean(resolvedPath)
				cleanExtractDir := filepath.Clean(extractDir)

				escapesExtraction = !strings.HasPrefix(cleanResolved, cleanExtractDir)

				if escapesExtraction {
					t.Errorf("critical issue!... symlink escapes extraction dir: %s → %s", relPath, target)
					t.Logf("  symlink resolves to: %s (outside extraction directory)", cleanResolved)
					findings.symlinkVulnerabilities = append(findings.symlinkVulnerabilities,
						fmt.Sprintf("relative symlink escape: %s → %s (resolves to %s)", relPath, target, cleanResolved))
				}
			}

			findings.symlinksFound = append(findings.symlinksFound, forensicSymlink{
				path:              relPath,
				target:            target,
				escapesExtraction: escapesExtraction,
				resolvedPath:      resolvedPath,
			})
		} else {
			// regular file or directory - collect silently
			if info.IsDir() {
				findings.directories = append(findings.directories, relPath)
			} else {
				findings.regularFiles = append(findings.regularFiles, relPath)
			}
		}
		return nil
	})

	return findings
}

// checkFileOutsideExtraction checks if a file was written outside the extraction directory.
// Returns true if the file exists (vulnerability), false otherwise. Silent on success.
func checkFileOutsideExtraction(t *testing.T, filePath string) bool {
	t.Helper()

	if stat, err := os.Stat(filePath); err == nil {
		content, _ := os.ReadFile(filePath)
		t.Errorf("critical issue!... file written OUTSIDE extraction directory!")
		t.Logf("  location: %s", filePath)
		t.Logf("  size: %d bytes", stat.Size())
		t.Logf("  content: %s", string(content))
		t.Logf("  ...this means an attacker can write files to arbitrary locations on the filesystem")
		return true
	}
	// no file found outside extraction directory...
	return false
}

// checkSymlinkCreation verifies if a symlink was created at the expected path and reports
// whether it points outside the extraction directory. Silent unless a symlink is found.
func checkSymlinkCreation(t *testing.T, symlinkPath, extractDir, expectedTarget string) bool {
	t.Helper()

	if linfo, err := os.Lstat(symlinkPath); err == nil {
		if linfo.Mode()&os.ModeSymlink != 0 {
			target, _ := os.Readlink(symlinkPath)

			if expectedTarget != "" && target == expectedTarget {
				t.Errorf("critical issue!... symlink pointing outside extraction dir was created!")
				t.Logf("  Symlink: %s → %s", symlinkPath, target)
				return true
			}

			// Check if it escapes even if target doesn't match expected
			if filepath.IsAbs(target) {
				cleanExtractDir := filepath.Clean(extractDir)
				if !strings.HasPrefix(filepath.Clean(target), cleanExtractDir) {
					t.Errorf("critical issue!... absolute symlink escapes extraction dir!")
					t.Logf("  symlink: %s → %s", symlinkPath, target)
					return true
				}
			}
		}
		// if it exists but is not a symlink, that's good (attack was thwarted)...
	}

	return false
}

// createMaliciousZipWithSymlink creates a ZIP archive containing a symlink entry pointing to an arbitrary target,
// followed by a file entry that attempts to write through that symlink.
// returns the path to the created ZIP archive.
func createMaliciousZipWithSymlink(t *testing.T, tempDir, symlinkName, symlinkTarget, fileName string) string {
	t.Helper()

	maliciousZip := filepath.Join(tempDir, "malicious.zip")
	zipFile, err := os.Create(maliciousZip)
	require.NoError(t, err)
	defer zipFile.Close()

	zw := zip.NewWriter(zipFile)

	// create parent directories if the symlink is nested
	if dir := filepath.Dir(symlinkName); dir != "." {
		dirHeader := &zip.FileHeader{
			Name:   dir + "/",
			Method: zip.Store,
		}
		dirHeader.SetMode(os.ModeDir | 0755)
		_, err = zw.CreateHeader(dirHeader)
		require.NoError(t, err)
	}

	// create symlink entry pointing outside extraction directory
	// note: ZIP format stores symlinks as regular files with the target path as content
	symlinkHeader := &zip.FileHeader{
		Name:   symlinkName,
		Method: zip.Store,
	}
	symlinkHeader.SetMode(os.ModeSymlink | 0755)

	symlinkWriter, err := zw.CreateHeader(symlinkHeader)
	require.NoError(t, err)

	// write the symlink target as the file content (this is how ZIP stores symlinks)
	_, err = symlinkWriter.Write([]byte(symlinkTarget))
	require.NoError(t, err)

	// create file entry that will be written through the symlink
	if fileName != "" {
		payloadContent := []byte("MALICIOUS PAYLOAD - This should NOT be written outside extraction dir!")
		payloadHeader := &zip.FileHeader{
			Name:   fileName,
			Method: zip.Deflate,
		}
		payloadHeader.SetMode(0644)

		payloadWriter, err := zw.CreateHeader(payloadHeader)
		require.NoError(t, err)

		_, err = payloadWriter.Write(payloadContent)
		require.NoError(t, err)
	}

	require.NoError(t, zw.Close())
	require.NoError(t, zipFile.Close())

	return maliciousZip
}
