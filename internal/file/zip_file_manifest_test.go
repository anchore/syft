package file

import (
	"encoding/json"
	"os"
	"path"
	"testing"
)

func TestNewZipFileManifest(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	sourceDirPath := path.Join(cwd, "test-fixtures", "zip-source")
	nestedArchiveFilePath := path.Join(sourceDirPath, "nested.zip")
	err = createZipArchive(t, sourceDirPath, nestedArchiveFilePath)
	if err != nil {
		t.Fatalf("unable to create nested archive for test fixture: %+v", err)
	}

	cleanup, archiveFilePath, err := setupZipFileTest(t, sourceDirPath)
	//goland:noinspection GoNilness
	defer fatalIfError(t, cleanup)
	if err != nil {
		t.Fatal(err)
	}

	actual, err := NewZipFileManifest(archiveFilePath)
	if err != nil {
		t.Fatalf("unable to extract from unzip archive: %+v", err)
	}

	if len(expectedZipArchiveEntries) != len(actual) {
		t.Fatalf("mismatched manifest: %d != %d", len(actual), len(expectedZipArchiveEntries))
	}

	for _, e := range expectedZipArchiveEntries {
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
