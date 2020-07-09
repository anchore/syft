package file

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/anchore/imgbom/internal/log"
)

const (
	_  = iota
	KB = 1 << (10 * iota)
	MB
	GB
)

const readLimit = 2 * GB

type extractRequest map[string]struct{}

func newExtractRequest(paths ...string) extractRequest {
	results := make(extractRequest)
	for _, p := range paths {
		results[p] = struct{}{}
	}
	return results
}

func ExtractFilesFromZip(archivePath string, paths ...string) (map[string]string, error) {
	request := newExtractRequest(paths...)

	results := make(map[string]string)
	zipReader, err := zip.OpenReader(archivePath)
	if err != nil {
		return nil, fmt.Errorf("unable to open zip archive (%s): %w", archivePath, err)
	}
	defer func() {
		err = zipReader.Close()
		if err != nil {
			log.Errorf("unable to close zip archive (%s): %w", archivePath, err)
		}
	}()

	for _, file := range zipReader.Reader.File {
		if _, ok := request[file.Name]; !ok {
			// this file path is not of interest
			continue
		}

		zippedFile, err := file.Open()
		if err != nil {
			return nil, fmt.Errorf("unable to read file=%q from zip=%q: %w", file.Name, archivePath, err)
		}

		if file.FileInfo().IsDir() {
			return nil, fmt.Errorf("unable to extract directories, only files: %s", file.Name)
		}

		var buffer bytes.Buffer

		// limit the zip reader on each file read to prevent decompression bomb attacks
		numBytes, err := io.Copy(&buffer, io.LimitReader(zippedFile, readLimit))
		if numBytes >= readLimit || errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("zip read limit hit (potential decompression bomb attack)")
		}
		if err != nil {
			return nil, fmt.Errorf("unable to copy source=%q for zip=%q: %w", file.Name, archivePath, err)
		}

		results[file.Name] = buffer.String()

		err = zippedFile.Close()
		if err != nil {
			return nil, fmt.Errorf("unable to close source file=%q from zip=%q: %w", file.Name, archivePath, err)
		}
	}
	return results, nil
}

func UnzipToDir(archivePath, targetDir string) error {
	zipReader, err := zip.OpenReader(archivePath)
	if err != nil {
		return fmt.Errorf("unable to open zip archive (%s): %w", archivePath, err)
	}
	defer func() {
		err = zipReader.Close()
		if err != nil {
			log.Errorf("unable to close zip archive (%s): %w", archivePath, err)
		}
	}()

	for _, file := range zipReader.Reader.File {
		// the zip-slip attack protection is still being erroneously detected
		// nolint:gosec
		expandedFilePath := filepath.Clean(filepath.Join(targetDir, file.Name))

		// protect against zip slip attacks (traversing unintended parent paths from maliciously crafted relative-path entries)
		if !strings.HasPrefix(expandedFilePath, filepath.Clean(targetDir)+string(os.PathSeparator)) {
			return fmt.Errorf("potential zip slip attack: %q", expandedFilePath)
		}

		err = extractSingleFile(file, expandedFilePath, archivePath)
		if err != nil {
			return err
		}
	}
	return nil
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
		numBytes, err := io.Copy(outputFile, io.LimitReader(zippedFile, readLimit))
		if numBytes >= readLimit || errors.Is(err, io.EOF) {
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

type ZipManifest map[string]os.FileInfo

func newZipManifest() ZipManifest {
	return make(ZipManifest)
}

func (z ZipManifest) Add(entry string, info os.FileInfo) {
	z[entry] = info
}

func (z ZipManifest) GlobMatch(pattern string) []string {
	results := make([]string, 0)
	for entry := range z {
		if GlobMatch(pattern, entry) {
			results = append(results, entry)
		}
	}
	return results
}

func ZipFileManifest(archivePath string) (ZipManifest, error) {
	zipReader, err := zip.OpenReader(archivePath)
	manifest := newZipManifest()
	if err != nil {
		return manifest, fmt.Errorf("unable to open zip archive (%s): %w", archivePath, err)
	}
	defer func() {
		err = zipReader.Close()
		if err != nil {
			log.Errorf("unable to close zip archive (%s): %w", archivePath, err)
		}
	}()

	for _, file := range zipReader.Reader.File {
		manifest.Add(file.Name, file.FileInfo())
	}
	return manifest, nil
}
