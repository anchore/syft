package file

import (
	"crypto/sha256"
	"encoding/json"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/go-test/deep"
)

func generateFixture(t *testing.T, archivePath string) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Errorf("unable to get cwd: %+v", err)
	}

	cmd := exec.Command("./generate-zip-fixture.sh", archivePath)
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
	archivePrefix, err := ioutil.TempFile("", "syft-ziputil-archive-TEST-")
	if err != nil {
		t.Fatalf("unable to create tempfile: %+v", err)
	}
	defer os.Remove(archivePrefix.Name())
	// the zip utility will add ".zip" to the end of the given name
	archivePath := archivePrefix.Name() + ".zip"
	defer os.Remove(archivePath)
	t.Logf("archive path: %s", archivePath)

	generateFixture(t, archivePrefix.Name())

	contentsDir, err := ioutil.TempDir("", "syft-ziputil-contents-TEST-")
	if err != nil {
		t.Fatalf("unable to create tempdir: %+v", err)
	}
	defer os.RemoveAll(contentsDir)

	t.Logf("content path: %s", contentsDir)

	cwd, err := os.Getwd()
	if err != nil {
		t.Errorf("unable to get cwd: %+v", err)
	}

	t.Logf("running from: %s", cwd)

	// note: zip utility already includes "zip-source" as a parent dir for all contained files
	goldenRootDir := filepath.Join(cwd, "test-fixtures")
	expectedPaths := 4
	observedPaths := 0

	err = UnzipToDir(archivePath, contentsDir)
	if err != nil {
		t.Fatalf("unable to unzip archive: %+v", err)
	}

	// compare the source dir tree and the unzipped tree
	err = filepath.Walk(filepath.Join(contentsDir, "zip-source"),
		func(path string, info os.FileInfo, err error) error {
			t.Logf("unzipped path: %s", path)
			observedPaths++
			if err != nil {
				t.Fatalf("this should not happen")
				return err
			}

			goldenPath := filepath.Join(goldenRootDir, strings.TrimPrefix(path, contentsDir))

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
		t.Errorf("missed test paths: %d!=%d", observedPaths, expectedPaths)
	}

}

func TestExtractFilesFromZipFile(t *testing.T) {
	archivePrefix, err := ioutil.TempFile("", "syft-ziputil-archive-TEST-")
	if err != nil {
		t.Fatalf("unable to create tempfile: %+v", err)
	}
	defer os.Remove(archivePrefix.Name())
	// the zip utility will add ".zip" to the end of the given name
	archivePath := archivePrefix.Name() + ".zip"
	defer os.Remove(archivePath)
	t.Logf("archive path: %s", archivePath)

	generateFixture(t, archivePrefix.Name())

	cwd, err := os.Getwd()
	if err != nil {
		t.Errorf("unable to get cwd: %+v", err)
	}

	t.Logf("running from: %s", cwd)

	aFilePath := filepath.Join("zip-source", "some-dir", "a-file.txt")
	bFilePath := filepath.Join("zip-source", "b-file.txt")

	expected := map[string]string{
		aFilePath: "A file! nice!",
		bFilePath: "B file...",
	}

	actual, err := ContentsFromZip(archivePath, aFilePath, bFilePath)
	if err != nil {
		t.Fatalf("unable to extract from unzip archive: %+v", err)
	}

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

func TestZipFileManifest(t *testing.T) {
	archivePrefix, err := ioutil.TempFile("", "syft-ziputil-archive-TEST-")
	if err != nil {
		t.Fatalf("unable to create tempfile: %+v", err)
	}
	defer os.Remove(archivePrefix.Name())
	// the zip utility will add ".zip" to the end of the given name
	archivePath := archivePrefix.Name() + ".zip"
	defer os.Remove(archivePath)
	t.Logf("archive path: %s", archivePath)

	generateFixture(t, archivePrefix.Name())

	cwd, err := os.Getwd()
	if err != nil {
		t.Errorf("unable to get cwd: %+v", err)
	}

	t.Logf("running from: %s", cwd)

	expected := []string{
		filepath.Join("zip-source") + string(os.PathSeparator),
		filepath.Join("zip-source", "some-dir") + string(os.PathSeparator),
		filepath.Join("zip-source", "some-dir", "a-file.txt"),
		filepath.Join("zip-source", "b-file.txt"),
	}

	actual, err := NewZipFileManifest(archivePath)
	if err != nil {
		t.Fatalf("unable to extract from unzip archive: %+v", err)
	}

	if len(expected) != len(actual) {
		t.Fatalf("mismatched manifest: %d != %d", len(actual), len(expected))
	}

	for _, e := range expected {
		_, ok := actual[e]
		if !ok {
			t.Errorf("missing path: %s", e)
		}
	}

	if t.Failed() {

		b, err := json.MarshalIndent(actual, "", "  ")
		if err != nil {
			t.Fatalf("can't show results: %+v", err)
		}

		t.Errorf("full result: %s", string(b))
	}

}
