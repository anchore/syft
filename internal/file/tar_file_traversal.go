package file

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/mholt/archiver/v3"
)

// ExtractGlobsFromTarToUniqueTempFile extracts paths matching the given globs within the given archive to a temporary directory, returning file openers for each file extracted.
func ExtractGlobsFromTarToUniqueTempFile(archivePath, dir string, globs ...string) (map[string]Opener, error) {
	results := make(map[string]Opener)

	// don't allow for full traversal, only select traversal from given paths
	if len(globs) == 0 {
		return results, nil
	}

	visitor := func(file archiver.File) error {
		defer file.Close()

		// ignore directories
		if file.FileInfo.IsDir() {
			return nil
		}

		// ignore any filename that doesn't match the given globs...
		if !matchesAnyGlob(file.Name(), globs...) {
			return nil
		}

		// we have a file we want to extract....
		tempFilePrefix := filepath.Base(filepath.Clean(file.Name())) + "-"
		tempFile, err := os.CreateTemp(dir, tempFilePrefix)
		if err != nil {
			return fmt.Errorf("unable to create temp file: %w", err)
		}
		// we shouldn't try and keep the tempFile open as the returned result may have several files, which takes up
		// resources (leading to "too many open files"). Instead we'll return a file opener to the caller which
		// provides a ReadCloser. It is up to the caller to handle closing the file explicitly.
		defer tempFile.Close()

		if err := safeCopy(tempFile, file.ReadCloser); err != nil {
			return fmt.Errorf("unable to copy source=%q for tar=%q: %w", file.Name(), archivePath, err)
		}

		results[file.Name()] = Opener{path: tempFile.Name()}

		return nil
	}

	return results, archiver.Walk(archivePath, visitor)
}

func matchesAnyGlob(name string, globs ...string) bool {
	for _, glob := range globs {
		if matches, err := doublestar.PathMatch(glob, name); err == nil && matches {
			return true
		}
	}
	return false
}
