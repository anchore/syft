//go:build !windows
// +build !windows

package file

import (
	"context"
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
	err = ensureNestedZipExists(t, sourceDirPath)
	if err != nil {
		t.Fatal(err)
	}

	archiveFilePath := setupZipFileTest(t, sourceDirPath, false)

	actual, err := NewZipFileManifest(context.Background(), archiveFilePath)
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

func TestNewZip64FileManifest(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	sourceDirPath := path.Join(cwd, "test-fixtures", "zip-source")
	archiveFilePath := setupZipFileTest(t, sourceDirPath, true)

	actual, err := NewZipFileManifest(context.Background(), archiveFilePath)
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

func TestZipFileManifest_GlobMatch(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	sourceDirPath := path.Join(cwd, "test-fixtures", "zip-source")
	err = ensureNestedZipExists(t, sourceDirPath)
	if err != nil {
		t.Fatal(err)
	}

	archiveFilePath := setupZipFileTest(t, sourceDirPath, false)

	z, err := NewZipFileManifest(context.Background(), archiveFilePath)
	if err != nil {
		t.Fatalf("unable to extract from unzip archive: %+v", err)
	}

	cases := []struct {
		glob     string
		expected string
	}{
		{
			"/b*",
			"b-file.txt",
		},
		{
			"*/a-file.txt",
			"some-dir/a-file.txt",
		},
		{
			"*/A-file.txt",
			"some-dir/a-file.txt",
		},
		{
			"**/*.zip",
			"nested.zip",
		},
	}

	for _, tc := range cases {
		t.Run(tc.glob, func(t *testing.T) {
			glob := tc.glob

			results := z.GlobMatch(true, glob)

			if len(results) == 1 && results[0] == tc.expected {
				return
			}

			t.Errorf("unexpected results for glob '%s': %+v", glob, results)
		})
	}
}
