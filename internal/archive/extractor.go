package archive

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/mholt/archives"

	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/cataloging"
)

// Extractor extracts archive contents to a destination directory.
type Extractor interface {
	// CanExtract returns true if this extractor can handle the given file.
	CanExtract(ctx context.Context, path string, reader io.ReadSeeker) bool

	// Extract extracts the archive contents to destDir, respecting the given limits.
	// Returns the number of files extracted and total bytes written.
	Extract(ctx context.Context, path string, destDir string, limits ExtractionLimits) (ExtractionResult, error)
}

// ExtractionLimits defines safety limits for archive extraction.
type ExtractionLimits struct {
	MaxExtractionSizeBytes int64
	MaxFileCount           int
}

// ExtractionResult holds the result of an extraction operation.
type ExtractionResult struct {
	FilesExtracted int
	BytesWritten   int64
}

// DefaultExtractionLimits returns limits from the given config.
func DefaultExtractionLimits(cfg cataloging.ArchiveSearchConfig) ExtractionLimits {
	return ExtractionLimits{
		MaxExtractionSizeBytes: cfg.MaxExtractionSizeBytes,
		MaxFileCount:           cfg.MaxFileCount,
	}
}

// DefaultExtractors returns the set of built-in archive extractors.
func DefaultExtractors() []Extractor {
	return []Extractor{
		&ZipExtractor{},
		&TarExtractor{},
	}
}

// FindExtractor finds an extractor that can handle the given file, or nil if none can.
func FindExtractor(ctx context.Context, extractors []Extractor, path string) Extractor {
	f, err := os.Open(path)
	if err != nil {
		log.Tracef("unable to open file for archive detection: %v", err)
		return nil
	}
	defer f.Close()

	for _, ext := range extractors {
		if ext.CanExtract(ctx, path, f) {
			return ext
		}
		// reset for next extractor
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			log.Tracef("unable to seek file for archive detection: %v", err)
			return nil
		}
	}
	return nil
}

// IsExcludedExtension checks if a file path has an excluded extension.
func IsExcludedExtension(path string, excludeExtensions []string) bool {
	for _, ext := range excludeExtensions {
		if strings.HasSuffix(strings.ToLower(path), strings.ToLower(ext)) {
			return true
		}
	}
	return false
}

// ZipExtractor extracts zip-based archives (zip, jar, war, ear, etc.).
type ZipExtractor struct{}

func (z *ZipExtractor) CanExtract(ctx context.Context, path string, reader io.ReadSeeker) bool {
	format, _, err := intFile.IdentifyArchive(ctx, path, reader)
	if err != nil {
		return false
	}
	_, ok := format.(archives.Zip)
	return ok
}

func (z *ZipExtractor) Extract(ctx context.Context, path string, destDir string, limits ExtractionLimits) (ExtractionResult, error) {
	var result ExtractionResult

	f, err := os.Open(path)
	if err != nil {
		return result, fmt.Errorf("unable to open zip archive %q: %w", path, err)
	}
	defer f.Close()

	return result, archives.Zip{}.Extract(ctx, f, func(ctx context.Context, file archives.FileInfo) error {
		if file.IsDir() {
			joinedPath, err := intFile.SafeJoin(destDir, file.NameInArchive)
			if err != nil {
				return err
			}
			return os.MkdirAll(joinedPath, file.Mode())
		}

		if limits.MaxFileCount > 0 && result.FilesExtracted >= limits.MaxFileCount {
			return fmt.Errorf("archive file count limit reached (%d files)", limits.MaxFileCount)
		}

		joinedPath, err := intFile.SafeJoin(destDir, file.NameInArchive)
		if err != nil {
			return err
		}

		if err := os.MkdirAll(filepath.Dir(joinedPath), 0o755); err != nil {
			return fmt.Errorf("unable to create parent dir: %w", err)
		}

		return extractFileWithLimits(file, joinedPath, &result, limits)
	})
}

// TarExtractor extracts tar-based archives (tar, tar.gz, tar.bz2, tar.xz, tar.zst).
type TarExtractor struct{}

func (t *TarExtractor) CanExtract(ctx context.Context, path string, reader io.ReadSeeker) bool {
	format, _, err := intFile.IdentifyArchive(ctx, path, reader)
	if err != nil {
		return false
	}
	// mholt/archives returns a compound type for tar+compression, check if it's an extractor but not a zip
	if _, isZip := format.(archives.Zip); isZip {
		return false
	}
	_, ok := format.(archives.Extractor)
	return ok
}

func (t *TarExtractor) Extract(ctx context.Context, path string, destDir string, limits ExtractionLimits) (ExtractionResult, error) {
	var result ExtractionResult

	f, err := os.Open(path)
	if err != nil {
		return result, fmt.Errorf("unable to open tar archive %q: %w", path, err)
	}
	defer f.Close()

	format, readerAfterIdentify, err := intFile.IdentifyArchive(ctx, path, f)
	if err != nil {
		return result, fmt.Errorf("unable to identify archive format for %q: %w", path, err)
	}

	extractor, ok := format.(archives.Extractor)
	if !ok {
		return result, fmt.Errorf("file format does not support extraction: %s", path)
	}

	// use the reader returned by IdentifyArchive since it may have consumed some bytes
	extractReader := readerAfterIdentify
	if extractReader == nil {
		extractReader = f
	}

	return result, extractor.Extract(ctx, extractReader, func(ctx context.Context, file archives.FileInfo) error {
		if file.IsDir() {
			joinedPath, err := intFile.SafeJoin(destDir, file.NameInArchive)
			if err != nil {
				return err
			}
			return os.MkdirAll(joinedPath, file.Mode())
		}

		if limits.MaxFileCount > 0 && result.FilesExtracted >= limits.MaxFileCount {
			return fmt.Errorf("archive file count limit reached (%d files)", limits.MaxFileCount)
		}

		joinedPath, err := intFile.SafeJoin(destDir, file.NameInArchive)
		if err != nil {
			return err
		}

		if err := os.MkdirAll(filepath.Dir(joinedPath), 0o755); err != nil {
			return fmt.Errorf("unable to create parent dir: %w", err)
		}

		return extractFileWithLimits(file, joinedPath, &result, limits)
	})
}

// extractFileWithLimits extracts a single file from an archive, respecting size limits.
func extractFileWithLimits(file archives.FileInfo, destPath string, result *ExtractionResult, limits ExtractionLimits) error {
	src, err := file.Open()
	if err != nil {
		return fmt.Errorf("unable to open archive entry %q: %w", file.NameInArchive, err)
	}
	defer src.Close()

	dst, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
	if err != nil {
		return fmt.Errorf("unable to create dest file %q: %w", destPath, err)
	}
	defer dst.Close()

	var reader io.Reader = src

	// enforce per-archive total size limit
	if limits.MaxExtractionSizeBytes > 0 {
		remaining := limits.MaxExtractionSizeBytes - result.BytesWritten
		if remaining <= 0 {
			return fmt.Errorf("archive extraction size limit reached (%d bytes)", limits.MaxExtractionSizeBytes)
		}
		reader = io.LimitReader(src, remaining+1) // +1 to detect exceeding the limit
	}

	n, err := io.Copy(dst, reader)
	result.BytesWritten += n
	result.FilesExtracted++

	if limits.MaxExtractionSizeBytes > 0 && result.BytesWritten > limits.MaxExtractionSizeBytes {
		return fmt.Errorf("archive extraction size limit reached (%d bytes)", limits.MaxExtractionSizeBytes)
	}

	return err
}
