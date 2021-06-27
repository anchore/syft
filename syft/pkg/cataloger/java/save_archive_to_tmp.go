package java

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/anchore/syft/internal"
)

func saveArchiveToTmp(reader io.Reader) (string, string, func() error, error) {
	generator := internal.RootTempDirGenerator.NewGenerator()
	tempDir, err := generator.NewDirectory("java-cataloger-content-cache")
	if err != nil {
		return "", "", func() error { return nil }, fmt.Errorf("unable to create tempdir for jar processing: %w", err)
	}
	cleanupFn := generator.Cleanup

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
	defer archiveFile.Close()

	_, err = io.Copy(archiveFile, reader)
	if err != nil {
		return contentDir, archivePath, cleanupFn, fmt.Errorf("unable to copy archive: %w", err)
	}

	return contentDir, archivePath, cleanupFn, nil
}
