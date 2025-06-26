package file

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/mholt/archives"
)

const (
	// represents the order of bytes
	_  = iota
	KB = 1 << (10 * iota)
	MB
	GB
)

type errZipSlipDetected struct {
	Prefix   string
	JoinArgs []string
}

func (e *errZipSlipDetected) Error() string {
	return fmt.Sprintf("paths are not allowed to resolve outside of the root prefix (%q). Destination: %q", e.Prefix, e.JoinArgs)
}

type zipTraversalRequest map[string]struct{}

func newZipTraverseRequest(paths ...string) zipTraversalRequest {
	results := make(zipTraversalRequest)
	for _, p := range paths {
		results[p] = struct{}{}
	}
	return results
}

// TraverseFilesInZip enumerates all paths stored within a zip archive using the visitor pattern.
func TraverseFilesInZip(ctx context.Context, archivePath string, visitor archives.FileHandler, paths ...string) error {
	request := newZipTraverseRequest(paths...)

	zipReader, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("unable to open zip archive (%s): %w", archivePath, err)
	}
	defer func() {
		if err := zipReader.Close(); err != nil {
			log.Errorf("unable to close zip archive (%s): %+v", archivePath, err)
		}
	}()

	return archives.Zip{}.Extract(ctx, zipReader, func(ctx context.Context, file archives.FileInfo) error {
		// if no paths are given then assume that all files should be traversed
		if len(paths) > 0 {
			if _, ok := request[file.NameInArchive]; !ok {
				// this file path is not of interest
				return nil
			}
		}

		return visitor(ctx, file)
	})
}

// ExtractFromZipToUniqueTempFile extracts select paths for the given archive to a temporary directory, returning file openers for each file extracted.
func ExtractFromZipToUniqueTempFile(ctx context.Context, archivePath, dir string, paths ...string) (map[string]Opener, error) {
	results := make(map[string]Opener)

	// don't allow for full traversal, only select traversal from given paths
	if len(paths) == 0 {
		return results, nil
	}

	visitor := func(ctx context.Context, file archives.FileInfo) error {
		tempfilePrefix := filepath.Base(filepath.Clean(file.NameInArchive)) + "-"
		tempFile, err := os.CreateTemp(dir, tempfilePrefix)
		if err != nil {
			return fmt.Errorf("unable to create temp file: %w", err)
		}
		// we shouldn't try and keep the tempfile open as the returned result may have several files, which takes up
		// resources (leading to "too many open files"). Instead we'll return a file opener to the caller which
		// provides a ReadCloser. It is up to the caller to handle closing the file explicitly.
		defer tempFile.Close()

		zippedFile, err := file.Open()
		if err != nil {
			return fmt.Errorf("unable to read file=%q from zip=%q: %w", file.NameInArchive, archivePath, err)
		}
		defer func() {
			if err := zippedFile.Close(); err != nil {
				log.Errorf("unable to close source file=%q from zip=%q: %+v", file.NameInArchive, archivePath, err)
			}
		}()

		if file.IsDir() {
			return fmt.Errorf("unable to extract directories, only files: %s", file.NameInArchive)
		}

		if err := safeCopy(tempFile, zippedFile); err != nil {
			return fmt.Errorf("unable to copy source=%q for zip=%q: %w", file.NameInArchive, archivePath, err)
		}

		results[file.NameInArchive] = Opener{path: tempFile.Name()}

		return nil
	}

	return results, TraverseFilesInZip(ctx, archivePath, visitor, paths...)
}

// ContentsFromZip extracts select paths for the given archive and returns a set of string contents for each path.
func ContentsFromZip(ctx context.Context, archivePath string, paths ...string) (map[string]string, error) {
	results := make(map[string]string)

	// don't allow for full traversal, only select traversal from given paths
	if len(paths) == 0 {
		return results, nil
	}

	visitor := func(ctx context.Context, file archives.FileInfo) error {
		zippedFile, err := file.Open()
		if err != nil {
			return fmt.Errorf("unable to read file=%q from zip=%q: %w", file.NameInArchive, archivePath, err)
		}
		defer func() {
			if err := zippedFile.Close(); err != nil {
				log.Errorf("unable to close source file=%q from zip=%q: %+v", file.NameInArchive, archivePath, err)
			}
		}()

		if file.IsDir() {
			return fmt.Errorf("unable to extract directories, only files: %s", file.NameInArchive)
		}

		var buffer bytes.Buffer
		if err := safeCopy(&buffer, zippedFile); err != nil {
			return fmt.Errorf("unable to copy source=%q for zip=%q: %w", file.NameInArchive, archivePath, err)
		}

		results[file.NameInArchive] = buffer.String()

		return nil
	}

	return results, TraverseFilesInZip(ctx, archivePath, visitor, paths...)
}

// UnzipToDir extracts a zip archive to a target directory.
func UnzipToDir(ctx context.Context, archivePath, targetDir string) error {
	visitor := func(ctx context.Context, file archives.FileInfo) error {
		joinedPath, err := safeJoin(targetDir, file.NameInArchive)
		if err != nil {
			return err
		}

		return extractSingleFile(file, joinedPath, archivePath)
	}

	return TraverseFilesInZip(ctx, archivePath, visitor)
}

// safeJoin ensures that any destinations do not resolve to a path above the prefix path.
func safeJoin(prefix string, dest ...string) (string, error) {
	joinResult := filepath.Join(append([]string{prefix}, dest...)...)
	cleanJoinResult := filepath.Clean(joinResult)
	if !strings.HasPrefix(cleanJoinResult, filepath.Clean(prefix)) {
		return "", &errZipSlipDetected{
			Prefix:   prefix,
			JoinArgs: dest,
		}
	}
	// why not return the clean path? the called may not be expected it from what should only be a join operation.
	return joinResult, nil
}

func extractSingleFile(file archives.FileInfo, expandedFilePath, archivePath string) error {
	zippedFile, err := file.Open()
	if err != nil {
		return fmt.Errorf("unable to read file=%q from zip=%q: %w", file.NameInArchive, archivePath, err)
	}
	defer func() {
		if err := zippedFile.Close(); err != nil {
			log.Errorf("unable to close source file=%q from zip=%q: %+v", file.NameInArchive, archivePath, err)
		}
	}()

	if file.IsDir() {
		err = os.MkdirAll(expandedFilePath, file.Mode())
		if err != nil {
			return fmt.Errorf("unable to create dir=%q from zip=%q: %w", expandedFilePath, archivePath, err)
		}
	} else {
		// Open an output file for writing
		outputFile, err := os.OpenFile(
			expandedFilePath,
			os.O_WRONLY|os.O_CREATE|os.O_TRUNC,
			file.Mode(),
		)
		if err != nil {
			return fmt.Errorf("unable to create dest file=%q from zip=%q: %w", expandedFilePath, archivePath, err)
		}
		defer func() {
			if err := outputFile.Close(); err != nil {
				log.Errorf("unable to close dest file=%q from zip=%q: %+v", outputFile.Name(), archivePath, err)
			}
		}()

		if err := safeCopy(outputFile, zippedFile); err != nil {
			return fmt.Errorf("unable to copy source=%q to dest=%q for zip=%q: %w", file.NameInArchive, outputFile.Name(), archivePath, err)
		}
	}

	return nil
}
