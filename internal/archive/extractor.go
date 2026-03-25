package archive

import (
	"context"
	"fmt"
	"io"
	"io/fs"
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

	return result, archives.Zip{}.Extract(ctx, f, func(_ context.Context, file archives.FileInfo) error {
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

		return extractFileWithLimits(file, joinedPath, destDir, &result, limits)
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

	return result, extractor.Extract(ctx, extractReader, func(_ context.Context, file archives.FileInfo) error {
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

		return extractFileWithLimits(file, joinedPath, destDir, &result, limits)
	})
}

// extractFileWithLimits extracts a single file from an archive, respecting size limits.
// Symlinks are written as real symlinks (only when the target stays inside destDir);
// non-regular file types other than symlinks are skipped to avoid writing bogus content.
func extractFileWithLimits(file archives.FileInfo, destPath, destDir string, result *ExtractionResult, limits ExtractionLimits) error {
	mode := file.Mode()
	if mode.Type()&fs.ModeSymlink != 0 {
		if err := writeSafeSymlink(file.LinkTarget, destPath, destDir); err != nil {
			log.WithFields("entry", file.NameInArchive, "target", file.LinkTarget, "error", err).Debug("skipping unsafe symlink in archive")
			return nil
		}
		result.FilesExtracted++
		return nil
	}
	if !mode.IsRegular() {
		// skip device nodes, fifos, sockets, etc. — they can't safely round-trip
		log.WithFields("entry", file.NameInArchive, "mode", mode).Debug("skipping non-regular archive entry")
		return nil
	}

	src, err := file.Open()
	if err != nil {
		return fmt.Errorf("unable to open archive entry %q: %w", file.NameInArchive, err)
	}
	defer src.Close()

	dst, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
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

// writeSafeSymlink creates a symlink at destPath only if target is relative and
// resolves — relative to destPath's directory — to a location inside destDir.
//
// Absolute targets are rejected outright: os.Symlink writes the literal target
// string, so an absolute target like "/etc/passwd" would resolve on the host
// filesystem when read, regardless of any safety check we performed against
// destDir at extraction time.
//
// NOTE: this guards against the single-symlink-escape pattern, but a malicious
// archive can still attempt a multi-step chain where two cooperating link
// entries together resolve outside destDir (e.g., one entry creates a benign
// link, a later entry writes through it). Fully preventing that requires
// either openat/O_NOFOLLOW per path component during extraction or
// transitively resolving every newly-created symlink against all prior ones
// — neither is implemented here.
func writeSafeSymlink(target, destPath, destDir string) error {
	if target == "" {
		return fmt.Errorf("empty link target")
	}
	if filepath.IsAbs(target) {
		return fmt.Errorf("absolute symlink target not allowed")
	}
	resolved := filepath.Join(filepath.Dir(destPath), target)
	cleanRoot := filepath.Clean(destDir)
	cleanResolved := filepath.Clean(resolved)
	if cleanResolved != cleanRoot && !strings.HasPrefix(cleanResolved, cleanRoot+string(filepath.Separator)) {
		return fmt.Errorf("symlink target escapes extraction root")
	}
	return os.Symlink(target, destPath)
}
