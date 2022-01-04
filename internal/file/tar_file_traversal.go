package file

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
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
		tempfilePrefix := filepath.Base(filepath.Clean(file.Name())) + "-"
		tempFile, err := ioutil.TempFile(dir, tempfilePrefix)
		if err != nil {
			return fmt.Errorf("unable to create temp file: %w", err)
		}
		// we shouldn't try and keep the tempfile open as the returned result may have several files, which takes up
		// resources (leading to "too many open files"). Instead we'll return a file opener to the caller which
		// provides a ReadCloser. It is up to the caller to handle closing the file explicitly.
		defer tempFile.Close()

		// limit the zip reader on each file read to prevent decompression bomb attacks
		numBytes, err := io.Copy(tempFile, io.LimitReader(file.ReadCloser, perFileReadLimit))
		if numBytes >= perFileReadLimit || errors.Is(err, io.EOF) {
			return fmt.Errorf("zip read limit hit (potential decompression bomb attack)")
		}
		if err != nil {
			return fmt.Errorf("unable to copy source=%q for zip=%q: %w", file.Name(), archivePath, err)
		}

		// the file pointer is at the end due to the copy operation, reset back to the beginning
		_, err = tempFile.Seek(0, io.SeekStart)
		if err != nil {
			return fmt.Errorf("unable to reset file pointer (%s): %w", tempFile.Name(), err)
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
