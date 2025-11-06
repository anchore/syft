package file

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/mholt/archives"
)

// ExtractGlobsFromTarToUniqueTempFile extracts paths matching the given globs within the given archive to a temporary directory, returning file openers for each file extracted.
func ExtractGlobsFromTarToUniqueTempFile(archivePath, dir string, globs ...string) (map[string]Opener, error) {
	results := make(map[string]Opener)

	// don't allow for full traversal, only select traversal from given paths
	if len(globs) == 0 {
		return results, nil
	}

	ctx := context.Background()
	fsys, err := archives.FileSystem(ctx, archivePath, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to open archive %q: %w", archivePath, err)
	}

	// Walk through all files in the archive
	err = fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// ignore directories
		if d.IsDir() {
			return nil
		}

		// ignore any filename that doesn't match the given globs...
		if !matchesAnyGlob(path, globs...) {
			return nil
		}

		// we have a file we want to extract....
		tempFilePrefix := filepath.Base(filepath.Clean(path)) + "-"
		tempFile, err := os.CreateTemp(dir, tempFilePrefix)
		if err != nil {
			return fmt.Errorf("unable to create temp file: %w", err)
		}
		// we shouldn't try and keep the tempFile open as the returned result may have several files, which takes up
		// resources (leading to "too many open files"). Instead we'll return a file opener to the caller which
		// provides a ReadCloser. It is up to the caller to handle closing the file explicitly.
		defer tempFile.Close()

		source, err := fsys.Open(path)
		if err != nil {
			return fmt.Errorf("unable to open source=%q for tar=%q: %w", path, archivePath, err)
		}
		defer source.Close()

		if err := safeCopy(tempFile, source); err != nil {
			return fmt.Errorf("unable to copy source=%q for tar=%q: %w", path, archivePath, err)
		}

		results[path] = Opener{path: tempFile.Name()}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return results, nil
}

func matchesAnyGlob(name string, globs ...string) bool {
	for _, glob := range globs {
		if matches, err := doublestar.PathMatch(glob, name); err == nil && matches {
			return true
		}
	}
	return false
}
