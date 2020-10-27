package file

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"syscall"
	"testing"
)

var expectedZipArchiveEntries = []string{
	filepath.Join("zip-source") + string(os.PathSeparator),
	filepath.Join("zip-source", "some-dir") + string(os.PathSeparator),
	filepath.Join("zip-source", "some-dir", "a-file.txt"),
	filepath.Join("zip-source", "b-file.txt"),
	filepath.Join("zip-source", "nested.zip"),
}

// fatalIfError calls the supplied function. If the function returns a non-nil error, t.Fatal(err) is called.
func fatalIfError(t *testing.T, fn func() error) {
	t.Helper()

	if fn == nil {
		return
	}

	err := fn()
	if err != nil {
		t.Fatal(err)
	}
}

// createZipArchive creates a new ZIP archive file at destinationArchivePath based on the directory found at
// sourceDirPath.
func createZipArchive(t *testing.T, sourceDirPath, destinationArchivePath string) error {
	t.Helper()

	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("unable to get cwd: %+v", err)
	}

	cmd := exec.Command("./generate-zip-fixture.sh", destinationArchivePath, path.Base(sourceDirPath))
	cmd.Dir = filepath.Join(cwd, "test-fixtures")

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("unable to start generate zip fixture script: %+v", err)
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
					return fmt.Errorf("failed to generate fixture: rc=%d", status.ExitStatus())
				}
			}
		} else {
			return fmt.Errorf("unable to get generate fixture script result: %+v", err)
		}
	}

	return nil
}

// setupZipFileTest encapsulates common test setup work for zip file tests. It returns a cleanup function,
// which should be called (typically deferred) by the caller, the path of the created zip archive, and an error,
// which should trigger a fatal test failure in the consuming test. The returned cleanup function will never be nil
// (even if there's an error), and it should always be called.
func setupZipFileTest(t *testing.T, sourceDirPath string) (func() error, string, error) {
	t.Helper()

	// Keep track of any needed cleanup work as we go
	var cleanupFns []func() error
	cleanup := func(fns []func() error) func() error {
		return func() error {
			for _, fn := range fns {
				err := fn()
				if err != nil {
					return err
				}
			}

			return nil
		}
	}

	archivePrefix, err := ioutil.TempFile("", "syft-ziputil-archive-TEST-")
	if err != nil {
		return cleanup(cleanupFns), "", fmt.Errorf("unable to create tempfile: %+v", err)
	}
	cleanupFns = append(cleanupFns, func() error { return os.Remove(archivePrefix.Name()) })

	destinationArchiveFilePath := archivePrefix.Name() + ".zip"
	t.Logf("archive path: %s", destinationArchiveFilePath)
	err = createZipArchive(t, sourceDirPath, destinationArchiveFilePath)
	cleanupFns = append(cleanupFns, func() error { return os.Remove(destinationArchiveFilePath) })
	if err != nil {
		return cleanup(cleanupFns), "", err
	}

	cwd, err := os.Getwd()
	if err != nil {
		return cleanup(cleanupFns), "", fmt.Errorf("unable to get cwd: %+v", err)
	}

	t.Logf("running from: %s", cwd)

	return cleanup(cleanupFns), destinationArchiveFilePath, nil
}
