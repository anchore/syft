package file

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/anchore/syft/internal/log"
)

const (
	_  = iota
	KB = 1 << (10 * iota)
	MB
	GB
)

const perFileReadLimit = 2 * GB

type zipTraversalRequest map[string]struct{}

func newZipTraverseRequest(paths ...string) zipTraversalRequest {
	results := make(zipTraversalRequest)
	for _, p := range paths {
		results[p] = struct{}{}
	}
	return results
}

func TraverseFilesInZip(archivePath string, visitor func(*zip.File) error, paths ...string) error {
	request := newZipTraverseRequest(paths...)

	zipReader, err := zip.OpenReader(archivePath)
	if err != nil {
		return fmt.Errorf("unable to open zip archive (%s): %w", archivePath, err)
	}
	defer func() {
		err = zipReader.Close()
		if err != nil {
			log.Errorf("unable to close zip archive (%s): %+v", archivePath, err)
		}
	}()

	for _, file := range zipReader.Reader.File {
		// if no paths are given then assume that all files should be traversed
		if len(paths) > 0 {
			if _, ok := request[file.Name]; !ok {
				// this file path is not of interest
				continue
			}
		}

		if err = visitor(file); err != nil {
			return err
		}
	}
	return nil
}

func ExtractFromZipToUniqueTempFile(archivePath, dir string, paths ...string) (map[string]io.Reader, error) {
	results := make(map[string]io.Reader)

	// don't allow for full traversal, only select traversal from given paths
	if len(paths) == 0 {
		return results, nil
	}

	visitor := func(file *zip.File) error {
		tempfilePrefix := filepath.Base(filepath.Clean(file.Name)) + "-"

		tempFile, err := ioutil.TempFile(dir, tempfilePrefix)
		if err != nil {
			return fmt.Errorf("unable to create temp file: %w", err)
		}

		zippedFile, err := file.Open()
		if err != nil {
			return fmt.Errorf("unable to read file=%q from zip=%q: %w", file.Name, archivePath, err)
		}

		if file.FileInfo().IsDir() {
			return fmt.Errorf("unable to extract directories, only files: %s", file.Name)
		}

		// limit the zip reader on each file read to prevent decompression bomb attacks
		numBytes, err := io.Copy(tempFile, io.LimitReader(zippedFile, perFileReadLimit))
		if numBytes >= perFileReadLimit || errors.Is(err, io.EOF) {
			return fmt.Errorf("zip read limit hit (potential decompression bomb attack)")
		}
		if err != nil {
			return fmt.Errorf("unable to copy source=%q for zip=%q: %w", file.Name, archivePath, err)
		}

		// the file pointer is at the end due to the copy operation, reset back to the beginning
		_, err = tempFile.Seek(0, io.SeekStart)
		if err != nil {
			return fmt.Errorf("unable to reset file pointer (%s): %w", tempFile.Name(), err)
		}

		results[file.Name] = tempFile

		err = zippedFile.Close()
		if err != nil {
			return fmt.Errorf("unable to close source file=%q from zip=%q: %w", file.Name, archivePath, err)
		}
		return nil
	}

	return results, TraverseFilesInZip(archivePath, visitor, paths...)
}

func ContentsFromZip(archivePath string, paths ...string) (map[string]string, error) {
	results := make(map[string]string)

	// don't allow for full traversal, only select traversal from given paths
	if len(paths) == 0 {
		return results, nil
	}

	visitor := func(file *zip.File) error {
		zippedFile, err := file.Open()
		if err != nil {
			return fmt.Errorf("unable to read file=%q from zip=%q: %w", file.Name, archivePath, err)
		}

		if file.FileInfo().IsDir() {
			return fmt.Errorf("unable to extract directories, only files: %s", file.Name)
		}

		var buffer bytes.Buffer

		// limit the zip reader on each file read to prevent decompression bomb attacks
		numBytes, err := io.Copy(&buffer, io.LimitReader(zippedFile, perFileReadLimit))
		if numBytes >= perFileReadLimit || errors.Is(err, io.EOF) {
			return fmt.Errorf("zip read limit hit (potential decompression bomb attack)")
		}
		if err != nil {
			return fmt.Errorf("unable to copy source=%q for zip=%q: %w", file.Name, archivePath, err)
		}

		results[file.Name] = buffer.String()

		err = zippedFile.Close()
		if err != nil {
			return fmt.Errorf("unable to close source file=%q from zip=%q: %w", file.Name, archivePath, err)
		}
		return nil
	}

	return results, TraverseFilesInZip(archivePath, visitor, paths...)
}

func UnzipToDir(archivePath, targetDir string) error {
	visitor := func(file *zip.File) error {
		// the zip-slip attack protection is still being erroneously detected
		// nolint:gosec
		expandedFilePath := filepath.Clean(filepath.Join(targetDir, file.Name))

		// protect against zip slip attacks (traversing unintended parent paths from maliciously crafted relative-path entries)
		if !strings.HasPrefix(expandedFilePath, filepath.Clean(targetDir)+string(os.PathSeparator)) {
			return fmt.Errorf("potential zip slip attack: %q", expandedFilePath)
		}

		err := extractSingleFile(file, expandedFilePath, archivePath)
		if err != nil {
			return err
		}
		return nil
	}

	return TraverseFilesInZip(archivePath, visitor)
}

func extractSingleFile(file *zip.File, expandedFilePath, archivePath string) error {
	zippedFile, err := file.Open()
	if err != nil {
		return fmt.Errorf("unable to read file=%q from zip=%q: %w", file.Name, archivePath, err)
	}

	if file.FileInfo().IsDir() {
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

		// limit the zip reader on each file read to prevent decompression bomb attacks
		numBytes, err := io.Copy(outputFile, io.LimitReader(zippedFile, perFileReadLimit))
		if numBytes >= perFileReadLimit || errors.Is(err, io.EOF) {
			return fmt.Errorf("zip read limit hit (potential decompression bomb attack)")
		}
		if err != nil {
			return fmt.Errorf("unable to copy source=%q to dest=%q for zip=%q: %w", file.Name, outputFile.Name(), archivePath, err)
		}

		err = outputFile.Close()
		if err != nil {
			return fmt.Errorf("unable to close dest file=%q from zip=%q: %w", outputFile.Name(), archivePath, err)
		}
	}

	err = zippedFile.Close()
	if err != nil {
		return fmt.Errorf("unable to close source file=%q from zip=%q: %w", file.Name, archivePath, err)
	}
	return nil
}
