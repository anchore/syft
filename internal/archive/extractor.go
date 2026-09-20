package archive

import (
	"bytes"
	"context"
	"errors"
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

// Extractor reads the entries of one archive into an EntrySink.
type Extractor interface {
	CanExtract(ctx context.Context, content Content) bool

	Extract(ctx context.Context, content Content, sink EntrySink, charge *Charge) (ExtractionResult, error)
}

// EntrySink is where an extractor puts the entries it reads out of an archive.
type EntrySink interface {
	AddEntry(f archives.FileInfo, result *ExtractionResult, charge *Charge) error

	// Finish is called once the last entry has been offered.
	Finish(result *ExtractionResult)
}

// TruncationReason names the bound that stopped an extraction early; empty means extracted in full.
type TruncationReason string

const (
	// TruncatedByDiskLimit: storing more content would exceed the scan's disk limit.
	TruncatedByDiskLimit TruncationReason = "disk limit"

	// TruncatedByIndexLimit: indexing more entries would exceed the record budget. Distinct from the
	// disk limit because the index is never written to disk, though the disk budget backstops it - see
	// Charge.IndexRecord.
	TruncatedByIndexLimit TruncationReason = "index limit"

	// TruncatedByLimit: a bound stopped extraction but the walker replaced the error naming which one.
	TruncatedByLimit TruncationReason = "configured limit"
)

// errTruncated stops an in-progress walk at a configured limit. It never escapes this package:
// extractors convert it into a successful, truncated ExtractionResult.
var errTruncated = errors.New("archive extraction stopped at a configured limit")

// ExtractionResult holds the result of an extraction. Reaching a limit is a truncation, not an error:
// content stored before the limit stays usable. A non-nil error from Extract means nothing usable was
// produced.
type ExtractionResult struct {
	// Truncation names the limit that stopped extraction early, or "" if none did.
	Truncation TruncationReason
}

func (r ExtractionResult) Truncated() bool {
	return r.Truncation != ""
}

// finishExtraction turns a walk stopped at a configured limit into a successful, truncated result.
// Both result and error are checked: walkers may wrap or replace the handler's error, so
// errors.Is(err, errTruncated) alone would report some truncations as failures.
func finishExtraction(result ExtractionResult, err error) (ExtractionResult, error) {
	if result.Truncated() || errors.Is(err, errTruncated) {
		if !result.Truncated() {
			// the walker swallowed the reason but passed the sentinel through
			result.Truncation = TruncatedByLimit
		}
		return result, nil
	}
	return result, err
}

// DefaultLimits returns the scan-wide in-use limits from the given config.
func DefaultLimits(cfg cataloging.ArchiveSearchConfig) Limits {
	return Limits{
		MaxMemoryBytes: cfg.MaxMemoryBytes,
		MaxDiskBytes:   cfg.MaxDiskBytes,
	}
}

// DefaultExtractors returns the set of built-in archive extractors.
func DefaultExtractors() []Extractor {
	return []Extractor{
		&ZipExtractor{},
		&TarExtractor{},
	}
}

// FindExtractor finds an extractor that can handle the given archive content, or nil if none can.
func FindExtractor(ctx context.Context, extractors []Extractor, content Content) Extractor {
	for _, ext := range extractors {
		// every extractor sniffs from the start, whether the content is a file or a buffer
		if _, err := content.Reader.Seek(0, io.SeekStart); err != nil {
			log.Tracef("unable to seek archive content for detection: %v", err)
			return nil
		}
		if ext.CanExtract(ctx, content) {
			return ext
		}
	}
	return nil
}

// ZipExtractor extracts zip-based archives (zip, jar, war, ear, etc.).
type ZipExtractor struct{}

// CanExtract reports whether this content is a zip. Test order matters: head identification wins,
// because a tar holding one jar ends in that jar's EOCD record, so reading it as a zip would lose the
// rest of the tar. The EOCD record is consulted only when nothing identifies from the head, where it
// is the only test that sees a zip concatenated onto a launcher stub (e.g. a Spring Boot executable
// jar).
//
// IdentifyArchive matches on filename as well as content; dropping the name would run every format's
// content matcher against every candidate, far slower. The name cannot admit a non-archive, since
// files reach an extractor only after content sniffing (see
// Test_archiveCataloger_aMisnamedNonArchiveIsNotAnError).
func (z *ZipExtractor) CanExtract(ctx context.Context, content Content) bool {
	format, _, err := intFile.IdentifyArchive(ctx, content.Name, content.Reader)
	if err == nil {
		_, isZip := format.(archives.Zip)
		return isZip
	}

	if _, seekErr := content.Reader.Seek(0, io.SeekStart); seekErr != nil {
		return false
	}
	return HasZipEndOfCentralDirectory(content.Reader)
}

func (z *ZipExtractor) Extract(ctx context.Context, content Content, sink EntrySink, charge *Charge) (ExtractionResult, error) {
	var result ExtractionResult

	if _, err := content.Reader.Seek(0, io.SeekStart); err != nil {
		return result, fmt.Errorf("unable to seek zip archive %q: %w", content.Name, err)
	}

	err := archives.Zip{}.Extract(ctx, content.Reader, func(_ context.Context, file archives.FileInfo) error {
		return sink.AddEntry(file, &result, charge)
	})

	sink.Finish(&result)

	return finishExtraction(result, err)
}

// TarExtractor extracts tar-based archives (tar, tar.gz, tar.bz2, tar.xz, tar.zst).
type TarExtractor struct{}

// CanExtract reports whether the content identifies as an extractable non-zip format.
func (t *TarExtractor) CanExtract(ctx context.Context, content Content) bool {
	format, _, err := intFile.IdentifyArchive(ctx, content.Name, content.Reader)
	if err != nil {
		return false
	}
	if _, isZip := format.(archives.Zip); isZip {
		return false
	}
	// tar+compression comes back as a compound type, so test for the Extractor interface
	_, ok := format.(archives.Extractor)
	return ok
}

func (t *TarExtractor) Extract(ctx context.Context, content Content, sink EntrySink, charge *Charge) (ExtractionResult, error) {
	var result ExtractionResult

	if _, err := content.Reader.Seek(0, io.SeekStart); err != nil {
		return result, fmt.Errorf("unable to seek tar archive %q: %w", content.Name, err)
	}

	format, readerAfterIdentify, err := intFile.IdentifyArchive(ctx, content.Name, content.Reader)
	if err != nil {
		return result, fmt.Errorf("unable to identify archive format for %q: %w", content.Name, err)
	}

	extractor, ok := format.(archives.Extractor)
	if !ok {
		return result, fmt.Errorf("file format does not support extraction: %s", content.Name)
	}

	// use the reader returned by IdentifyArchive since it may have consumed some bytes
	var extractReader = readerAfterIdentify
	if extractReader == nil {
		extractReader = content.Reader
	}

	err = extractor.Extract(ctx, extractReader, func(_ context.Context, file archives.FileInfo) error {
		return sink.AddEntry(file, &result, charge)
	})

	sink.Finish(&result)

	return finishExtraction(result, err)
}

// resolvesInsideRoot reports whether writing to path lands inside root, following existing symlinks
// as the filesystem would. It guards the one filesystem write left in this package: an archive
// spilling into its work directory under an attacker-controlled name.
//
// The walk is component by component rather than one EvalSymlinks call because the leaf does not yet
// exist, which makes EvalSymlinks fail rather than answer. The first missing component ends the walk:
// anything created below it lands under an already-checked path.
func resolvesInsideRoot(root, path string) (bool, error) {
	// the root itself may sit under a symlinked directory (e.g. a macOS temp dir)
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return false, fmt.Errorf("unable to resolve extraction root: %w", err)
	}

	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false, err
	}
	if !isWithin(filepath.Join(realRoot, rel), realRoot) {
		return false, nil
	}

	current := realRoot
	for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)

		info, err := os.Lstat(current)
		if err != nil {
			if os.IsNotExist(err) {
				break
			}
			return false, err
		}
		if info.Mode()&fs.ModeSymlink == 0 {
			continue
		}

		resolved, err := resolveLink(current)
		if err != nil {
			return false, err
		}
		if !isWithin(resolved, realRoot) {
			return false, nil
		}
		current = resolved
	}

	return isWithin(current, realRoot), nil
}

// resolveLink returns where a symlink points, falling back to the lexically cleaned target when it
// does not exist yet - a dangling link still redirects a write.
func resolveLink(path string) (string, error) {
	target, err := os.Readlink(path)
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(path), target)
	}
	resolved, err := filepath.EvalSymlinks(target)
	if err != nil {
		if !os.IsNotExist(err) {
			return "", err
		}
		return filepath.Clean(target), nil
	}
	return resolved, nil
}

// isWithin reports whether path is root or beneath it, compared on path boundaries so a sibling
// sharing the prefix does not pass.
func isWithin(path, root string) bool {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(path))
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

// zipEOCDSignature is the end-of-central-directory record's signature. Readers seek to this record
// to find the central directory, which is why a zip with something prepended still opens.
var zipEOCDSignature = []byte{'P', 'K', 0x05, 0x06}

// maxZipEOCDSearch is how far back from the end the EOCD record can start: a 22 byte record plus a
// comment of up to 65535 bytes.
const maxZipEOCDSearch = 22 + 65535

// zipLocalFileHeaderSignature starts every entry in a zip. In a self-extracting archive the first
// one follows the stub, within reach of a bounded read of the head.
var zipLocalFileHeaderSignature = []byte{'P', 'K', 0x03, 0x04}

// maxAppendedArchiveStubBytes is how far into a file an appended archive is looked for. A Spring
// Boot launcher stub is about 9 KB; a longer stub hides its archive from the walk.
const maxAppendedArchiveStubBytes = 64 * 1024

// MayHideAnAppendedArchive reports whether the head of this stream contains a zip local file header,
// and returns a reader that replays what it consumed.
//
// A cheap, bounded pre-filter for HasZipEndOfCentralDirectory: reading every script, executable and
// unrecognized file to its end roughly doubles a scan, so only files showing an entry signature in
// their head are read in full. It narrows what is examined; it admits nothing on its own.
func MayHideAnAppendedArchive(r io.Reader) (io.Reader, bool) {
	head := make([]byte, maxAppendedArchiveStubBytes)
	n, err := io.ReadFull(r, head)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return io.MultiReader(bytes.NewReader(head[:n]), r), false
	}
	head = head[:n]
	return io.MultiReader(bytes.NewReader(head), r), bytes.Contains(head, zipLocalFileHeaderSignature)
}

// HasZipEndOfCentralDirectory reports whether the content ends in a zip end-of-central-directory
// record - the only part of a zip whose position is knowable without parsing. It identifies archives
// that head-based sniffing types as something else, such as a launcher stub with a zip appended,
// which mholt/archives extracts correctly via archive/zip.
func HasZipEndOfCentralDirectory(r ReaderAtSeeker) bool {
	size, err := r.Seek(0, io.SeekEnd)
	if err != nil || size < int64(len(zipEOCDSignature)) {
		return false
	}

	window := int64(maxZipEOCDSearch)
	if size < window {
		window = size
	}

	buf := make([]byte, window)
	if _, err := r.ReadAt(buf, size-window); err != nil && !errors.Is(err, io.EOF) {
		return false
	}

	return bytes.LastIndex(buf, zipEOCDSignature) >= 0
}
