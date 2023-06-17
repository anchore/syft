package file

import (
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
)

var expectedZipArchiveEntries = []string{
	"some-dir" + string(os.PathSeparator),
	filepath.Join("some-dir", "a-file.txt"),
	"b-file.txt",
	"nested.zip",
}

// createZipArchive creates a new ZIP archive file at destinationArchivePath based on the directory found at
// sourceDirPath. It forces a zip64 archive if zip64 is "0".
func createZipArchive(t testing.TB, sourceDirPath, destinationArchivePath string, zip64 bool) {
	t.Helper()

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("unable to get cwd: %+v", err)
	}
	zip64Arg := "0"
	if zip64 {
		zip64Arg = "1"
	}

	cmd := exec.Command("./generate-zip-fixture-from-source-dir.sh", destinationArchivePath, path.Base(sourceDirPath), zip64Arg)
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

func assertNoError(t testing.TB, fn func() error) func() {
	return func() {
		assert.NoError(t, fn())
	}
}

// setupZipFileTest encapsulates common test setup work for zip file tests. It returns a cleanup function,
// which should be called (typically deferred) by the caller, the path of the created zip archive, and an error,
// which should trigger a fatal test failure in the consuming test. The returned cleanup function will never be nil
// (even if there's an error), and it should always be called.
func setupZipFileTest(t testing.TB, sourceDirPath string, zip64 bool) string {
	t.Helper()

	archivePrefix := path.Join(t.TempDir(), "syft-ziputil-archive-TEST-")
	destinationArchiveFilePath := archivePrefix + ".zip"
	t.Logf("archive path: %s", destinationArchiveFilePath)
	createZipArchive(t, sourceDirPath, destinationArchiveFilePath, zip64)

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("unable to get cwd: %+v", err)
	}

	t.Logf("running from: %s", cwd)

	return destinationArchiveFilePath
}

// TODO: Consider moving any non-git asset generation to a task (e.g. make) that's run ahead of running go tests.
func ensureNestedZipExists(t *testing.T, sourceDirPath string) error {
	t.Helper()

	nestedArchiveFilePath := path.Join(sourceDirPath, "nested.zip")
	createZipArchive(t, sourceDirPath, nestedArchiveFilePath, false)

	return nil
}
