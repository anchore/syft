package archive

import (
	"fmt"
	"io/ioutil"
	"path/filepath"

	"github.com/anchore/syft/syft/file"
	"github.com/bmatcuk/doublestar/v4"
	"github.com/mholt/archiver/v3"
)

// ExtractGlobsFromTarToUniqueTempFile extracts paths matching the given globs within the given archive to a temporary directory, returning file openers for each file extracted.
func ExtractGlobsFromTarToUniqueTempFile(archivePath, dir string, globs ...string) (map[string]file.Opener, error) {
	results := make(map[string]file.Opener)

	// don't allow for full traversal, only select traversal from given paths
	if len(globs) == 0 {
		return results, nil
	}

	visitor := func(f archiver.File) error {
		defer f.Close()

		// ignore directories
		if f.FileInfo.IsDir() {
			return nil
		}

		// ignore any filename that doesn't match the given globs...
		if !matchesAnyGlob(f.Name(), globs...) {
			return nil
		}

		// we have a file we want to extract....
		tempfilePrefix := filepath.Base(filepath.Clean(f.Name())) + "-"
		tempFile, err := ioutil.TempFile(dir, tempfilePrefix)
		if err != nil {
			return fmt.Errorf("unable to create temp file: %w", err)
		}
		// we shouldn't try and keep the tempfile open as the returned result may have several files, which takes up
		// resources (leading to "too many open files"). Instead we'll return a file opener to the caller which
		// provides a ReadCloser. It is up to the caller to handle closing the file explicitly.
		defer tempFile.Close()

		if err := safeCopy(tempFile, f.ReadCloser); err != nil {
			return fmt.Errorf("unable to copy source=%q for tar=%q: %w", f.Name(), archivePath, err)
		}

		results[f.Name()] = file.NewOpener(tempFile.Name())

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
