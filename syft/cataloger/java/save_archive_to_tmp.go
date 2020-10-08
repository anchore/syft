package java

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/anchore/syft/internal/log"
)

func saveArchiveToTmp(reader io.Reader) (string, string, func(), error) {
	tempDir, err := ioutil.TempDir("", "syft-jar-contents-")
	if err != nil {
		return "", "", func() {}, fmt.Errorf("unable to create tempdir for jar processing: %w", err)
	}

	cleanupFn := func() {
		err = os.RemoveAll(tempDir)
		if err != nil {
			log.Errorf("unable to cleanup jar tempdir: %+v", err)
		}
	}

	archivePath := filepath.Join(tempDir, "archive")
	contentDir := filepath.Join(tempDir, "contents")

	err = os.Mkdir(contentDir, 0755)
	if err != nil {
		return contentDir, "", cleanupFn, fmt.Errorf("unable to create processing tempdir: %w", err)
	}

	archiveFile, err := os.Create(archivePath)
	if err != nil {
		return contentDir, "", cleanupFn, fmt.Errorf("unable to create archive: %w", err)
	}

	_, err = io.Copy(archiveFile, reader)
	if err != nil {
		return contentDir, archivePath, cleanupFn, fmt.Errorf("unable to copy archive: %w", err)
	}

	return contentDir, archivePath, cleanupFn, nil
}
