package file

import (
	"crypto/sha256"
	"encoding/json"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-test/deep"
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
	cleanup, archiveFilePath, err := setupZipFileTest(t, sourceDirPath)
	defer fatalIfError(t, cleanup)
	if err != nil {
		t.Fatal(err)
	}

	unzipDestinationDir, err := ioutil.TempDir("", "syft-ziputil-contents-TEST-")
	defer os.RemoveAll(unzipDestinationDir)
	if err != nil {
		t.Fatalf("unable to create tempdir: %+v", err)
	}

	t.Logf("content path: %s", unzipDestinationDir)

	expectedPaths := len(expectedZipArchiveEntries)
	observedPaths := 0

	err = UnzipToDir(archiveFilePath, unzipDestinationDir)
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
	archivePrefix, err := ioutil.TempFile("", "syft-ziputil-archive-TEST-")
	if err != nil {
		t.Fatalf("unable to create tempfile: %+v", err)
	}
	defer os.Remove(archivePrefix.Name())
	// the zip utility will add ".zip" to the end of the given name
	archivePath := archivePrefix.Name() + ".zip"
	defer os.Remove(archivePath)
	t.Logf("archive path: %s", archivePath)

	err = createZipArchive(t, "zip-source", archivePrefix.Name())
	if err != nil {
		t.Fatal(err)
	}

	cwd, err := os.Getwd()
	if err != nil {
		t.Errorf("unable to get cwd: %+v", err)
	}

	t.Logf("running from: %s", cwd)

	aFilePath := filepath.Join("some-dir", "a-file.txt")
	bFilePath := filepath.Join("b-file.txt")

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
