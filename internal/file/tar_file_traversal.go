package file

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/anchore/syft/internal/log"
	"github.com/bmatcuk/doublestar/v4"
	"github.com/mholt/archives"
)

// TraverseFilesInTar enumerates all paths stored within a tar archive using the visitor pattern.
func TraverseFilesInTar(ctx context.Context, archivePath string, visitor archives.FileHandler) error {
	tarReader, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("unable to open tar archive (%s): %w", archivePath, err)
	}
	defer func() {
		if err := tarReader.Close(); err != nil {
			log.Errorf("unable to close tar archive (%s): %+v", archivePath, err)
		}
	}()

	format, _, err := archives.Identify(ctx, archivePath, nil)
	if err != nil {
		return fmt.Errorf("failed to identify tar compression format: %w", err)
	}

	extractor, ok := format.(archives.Extractor)
	if !ok {
		return fmt.Errorf("file format does not support extraction: %s", archivePath)
	}

	return extractor.Extract(ctx, tarReader, visitor)
}

// ExtractGlobsFromTarToUniqueTempFile extracts paths matching the given globs within the given archive to a temporary directory, returning file openers for each file extracted.
func ExtractGlobsFromTarToUniqueTempFile(ctx context.Context, archivePath, dir string, globs ...string) (map[string]Opener, error) {
	results := make(map[string]Opener)

	// don't allow for full traversal, only select traversal from given paths
	if len(globs) == 0 {
		return results, nil
	}

	visitor := func(ctx context.Context, file archives.FileInfo) error {
		// ignore directories
		if file.IsDir() {
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

		packedFile, err := file.Open()
		if err != nil {
			return fmt.Errorf("unable to read file=%q from tar=%q: %w", file.NameInArchive, archivePath, err)
		}
		defer func() {
			if err := packedFile.Close(); err != nil {
				log.Errorf("unable to close source file=%q from tar=%q: %+v", file.NameInArchive, archivePath, err)
			}
		}()

		if err := safeCopy(tempFile, packedFile); err != nil {
			return fmt.Errorf("unable to copy source=%q for tar=%q: %w", file.Name(), archivePath, err)
		}

		results[file.Name()] = Opener{path: tempFile.Name()}

		return nil
	}

	return results, TraverseFilesInTar(ctx, archivePath, visitor)
}

func matchesAnyGlob(name string, globs ...string) bool {
	for _, glob := range globs {
		if matches, err := doublestar.PathMatch(glob, name); err == nil && matches {
			return true
		}
	}
	return false
}
