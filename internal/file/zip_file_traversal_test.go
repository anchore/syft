//go:build !windows
// +build !windows

package file

import (
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
			actual, err := safeJoin(test.prefix, test.args...)
			test.errAssertion(t, err)
			assert.Equal(t, test.expected, actual)
		})
	}
}
