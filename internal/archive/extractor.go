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

// Extractor extracts archive contents to a destination directory.
type Extractor interface {
	// CanExtract returns true if this extractor can handle the given archive content.
	CanExtract(ctx context.Context, content Content) bool

	// Extract writes the archive's entries into sink - one store per archive, not one file per entry -
	// respecting the given limits. Returns how many entries were written and how many bytes that took.
	Extract(ctx context.Context, content Content, sink EntrySink, limits ExtractionLimits) (ExtractionResult, error)
}

// EntrySink is where an extractor puts the entries it reads out of an archive.
//
// Two implementations exist because they store an archive differently and the difference is
// measurable: OverflowTar writes every entry into one tar on disk and is indexed by seek offset,
// while EntryStore holds entries in memory until a bound says otherwise and is indexed by the entries
// themselves. The extractors do not care which they were given, with one exception - see
// VerbatimSink.
type EntrySink interface {
	// AddEntry stores one entry of the archive.
	AddEntry(f archives.FileInfo, result *ExtractionResult, limits ExtractionLimits) error

	// Finish is called once the last entry has been offered, for whatever a sink has to write after
	// its content.
	Finish(result *ExtractionResult, limits ExtractionLimits)
}

// VerbatimSink is an EntrySink that stores archives in tar form, so a tar-family archive can be
// copied into it as it stands rather than decoded and re-encoded entry by entry.
//
// This is the one place the storage format shows through the extractor interface, and it is worth the
// leak: a tar.gz copied verbatim is one streamed decompression, where walking it costs a read per
// entry. A sink that does not store tars does not implement this and gets the entry-by-entry path.
type VerbatimSink interface {
	EntrySink
	CopyVerbatim(r io.Reader, result *ExtractionResult, limits ExtractionLimits) error
}

// ExtractionLimits defines safety limits for extracting one archive.
type ExtractionLimits struct {

	// Charge is this archive's draw on the scan's resource limiter. Entry bytes are charged to it as
	// they land, never from the size the entry declared, and a refused charge truncates the
	// extraction. A nil Charge enforces no byte bound.
	//
	// It is a handle rather than a remaining-bytes value because what it charges has to be given back
	// when the archive is released, and a value copied into a call cannot be.
	Charge *Charge
}

// TruncationReason names the configured bound that stopped an extraction early. The empty value
// means the archive was extracted in full.
type TruncationReason string

const (
	// TruncatedByDiskLimit means placing more of this archive's content would have taken the scan's
	// disk usage past the disk limit. Named rather than reported as a bare truncation because a breach
	// has to be attributed to the archive that triggered it, and saying which bound was reached is
	// half of that attribution.
	TruncatedByDiskLimit TruncationReason = "disk limit"

	// TruncatedByLimit means a bound stopped the extraction but the walker replaced the error that
	// said which one. Defensive: both bounds record their own reason on the result before stopping.
	TruncatedByLimit TruncationReason = "configured limit"
)

// errTruncated stops an in-progress archive walk when a configured limit is reached. It never
// escapes this package: the extractors convert it into a successful, truncated ExtractionResult.
var errTruncated = errors.New("archive extraction stopped at a configured limit")

// ExtractionResult holds the result of an extraction operation.
//
// Reaching a configured limit is NOT an error: it is a truncation. Whatever was written before the
// limit is left on disk and is usable, so callers can still catalog what was extracted rather than
// discarding the whole archive. Check Truncated to tell a complete extraction from a partial one;
// a non-nil error from Extract means the extraction failed and nothing usable was produced.
type ExtractionResult struct {
	// FilesExtracted counts the entries this archive's filesystem holds - the records its overflow tar
	// was indexed into: regular files, symlinks, and directory entries. It is the count after indexing
	// rather than the count written, so an entry dropped by an exclusion pattern is not counted as
	// present. Reported, not bounded.
	FilesExtracted int

	// BytesWritten is what this archive put on disk: every byte of the overflow tar, headers and block
	// padding included, because that is what the disk limit was charged for.
	BytesWritten int64

	// Truncation names the limit that stopped extraction early, or "" when the archive was
	// extracted in full.
	Truncation TruncationReason
}

// Truncated reports whether a configured limit stopped this extraction before the end of the
// archive.
func (r ExtractionResult) Truncated() bool {
	return r.Truncation != ""
}

// finishExtraction turns a walk that stopped at a configured limit into a successful, truncated
// result.
//
// The limit signal is carried on the result rather than only in the returned error because the
// underlying archive walkers are free to wrap or replace a handler's error, in which case
// errors.Is(err, errTruncated) would not match and a truncation would be reported as a failure -
// discarding an archive syft could have cataloged. The error is still checked, so a walker that
// passes it through cleanly is handled too.
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

// DefaultExtractionLimits returns the per-archive limits from the given config.
//
// Nothing is read from the config: every bound this scan enforces is an in-use limit held by the
// scan's limiter, and the only per-archive field left is the Charge the caller draws against it.
// The parameter stays so the two Default* constructors are called the same way, and so a per-archive
// bound that is genuinely per-archive has somewhere to land.
func DefaultExtractionLimits(_ cataloging.ArchiveSearchConfig) ExtractionLimits {
	return ExtractionLimits{}
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

// CanExtract reports whether this content is a zip, asking two questions in an order that matters.
//
// First, what does the content say it is, reading from the start? A format that identifies itself at
// offset zero is what this content is, and if that format is not zip then it is not a zip - a tar
// holding one jar ends in that jar's end-of-central-directory record, and reading it as a zip
// instead of as a tar would lose everything else the tar holds.
//
// Only when nothing identifies from the head is the end-of-central-directory record consulted. That
// record is what defines a zip - a reader locates the central directory through it - and it is the
// only thing that can see an archive whose head is something else entirely. A self-extracting
// archive is a launcher stub with a zip concatenated onto it, so no magic at offset zero can find
// it; the canonical case is a Spring Boot executable jar, a shell script followed by a whole zip.
//
// Identification is intFile.IdentifyArchive, which matches on the filename as well as the content,
// and it is left that way. Dropping the name makes the answer content's alone, which reads better -
// but archives.Identify with no path has to try every format's content matcher against every
// candidate, and measured on a stock ruby image that took the scan from 17 seconds to 45. The name
// cannot admit a non-archive in practice: a file only reaches an extractor after its sniffed content
// type put it in the candidate set, so the prose named notes.zip that this would wrongly identify is
// never offered here at all. `#content-based-archive-detection` is upheld by the candidate set, and
// Test_archiveCataloger_aMisnamedNonArchiveIsNotAnError is where that is asserted.
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

func (z *ZipExtractor) Extract(ctx context.Context, content Content, sink EntrySink, limits ExtractionLimits) (ExtractionResult, error) {
	var result ExtractionResult

	if _, err := content.Reader.Seek(0, io.SeekStart); err != nil {
		return result, fmt.Errorf("unable to seek zip archive %q: %w", content.Name, err)
	}

	// mholt/archives imposes no extraction target: the FileHandler is the caller's, so an entry can
	// be written into a tar header rather than onto the filesystem. Nothing about the library had to
	// be customized - the old code wrote files because the handler wrote files.
	err := archives.Zip{}.Extract(ctx, content.Reader, func(_ context.Context, file archives.FileInfo) error {
		return sink.AddEntry(file, &result, limits)
	})

	sink.Finish(&result, limits)

	return finishExtraction(result, err)
}

// TarExtractor extracts tar-based archives (tar, tar.gz, tar.bz2, tar.xz, tar.zst).
type TarExtractor struct{}

func (t *TarExtractor) CanExtract(ctx context.Context, content Content) bool {
	format, _, err := intFile.IdentifyArchive(ctx, content.Name, content.Reader)
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

func (t *TarExtractor) Extract(ctx context.Context, content Content, sink EntrySink, limits ExtractionLimits) (ExtractionResult, error) {
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

	// a tar handed to a sink that stores tars is not walked at all: a compressed tar is decompressed
	// once into the sink's file and a plain one is copied, and the entries are first looked at when
	// the file is indexed. Where the sink stores entries rather than a tar there is nothing to copy
	// into, so the tar is walked like any other archive.
	if verbatim, isVerbatim := sink.(VerbatimSink); isVerbatim {
		if plain, ok := tarStream(format, extractReader); ok {
			err = verbatim.CopyVerbatim(plain, &result, limits)
			if closeErr := plain.Close(); closeErr != nil {
				log.WithFields("archive", content.Name, "error", closeErr).Trace("unable to close decompressed tar stream")
			}
			return finishExtraction(result, err)
		}
	}

	// anything else - 7z, rar, or a tar going into a sink that does not store tars - is walked entry
	// by entry
	err = extractor.Extract(ctx, extractReader, func(_ context.Context, file archives.FileInfo) error {
		return sink.AddEntry(file, &result, limits)
	})

	sink.Finish(&result, limits)

	return finishExtraction(result, err)
}

// resolvesInsideRoot reports whether writing to path really lands inside root, following any symlink
// that already exists along the way the same way the filesystem will.
//
// The one filesystem write left in this package is the archive's own bytes overflowing into its work
// directory, under a name derived from where the archive was found - which inside another archive is
// attacker-controlled text. That is what this now guards; entries are tar headers and traverse no
// path at all. See overflowContent.
//
// It walks path one component at a time rather than calling filepath.EvalSymlinks on the whole
// thing, because the leaf of an entry being extracted does not exist yet, which makes EvalSymlinks
// fail rather than answer. The first component that does not exist ends the walk: nothing below it
// exists either, so whatever is created there is created fresh under a path already known to be
// inside the root.
func resolvesInsideRoot(root, path string) (bool, error) {
	// the root itself may sit under a symlinked directory (a temp dir on macOS, for one), so
	// containment is judged against its real location
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

// resolveLink returns where a symlink really points, falling back to the lexically cleaned target
// when the target does not exist yet - a dangling link still redirects a write.
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

// isWithin reports whether path is root or sits beneath it, compared on a path boundary rather than
// as a string prefix so a sibling sharing the prefix does not pass.
func isWithin(path, root string) bool {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(path))
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

// writeSafeSymlink creates a symlink at destPath only if target is relative and really resolves,
// relative to destPath's directory, to a location inside destDir.
//
// Absolute targets are rejected outright: os.Symlink writes the literal target
// string, so an absolute target like "/etc/passwd" would resolve on the host
// filesystem when read, regardless of any safety check we performed against
// destDir at extraction time.
//
// A relative target is resolved against the REAL location of destPath's directory, not against its
// lexical one, because two cooperating entries can otherwise each pass on their own and together
// point outside: a link to "." followed by a link to ".." inside it resolves lexically to the root
// while really landing above it, and repeating the pair climbs a level each time. The parent of
// every write is checked the same way before the write happens, so a link that slipped through here
// still could not be written through - this is the earlier of two refusals, not the only one.
//
// It has no caller since an archive's entries became headers in one tar rather than files on disk: a
// symlink entry is now a header write, which creates nothing and traverses nothing, and where the
// link points is decided inside the archive's own filetree. It is kept rather than retired because
// that is a judgement about every path that could write a link, not about this one call site, and
// because the reasoning above is the expensive part to reconstruct.
//
//nolint:unused // retained deliberately; see the note above
func writeSafeSymlink(target, destPath, destDir string) error {
	if target == "" {
		return fmt.Errorf("empty link target")
	}
	if filepath.IsAbs(target) {
		return fmt.Errorf("absolute symlink target not allowed")
	}

	realRoot, err := filepath.EvalSymlinks(destDir)
	if err != nil {
		return fmt.Errorf("unable to resolve extraction root: %w", err)
	}
	realParent, err := filepath.EvalSymlinks(filepath.Dir(destPath))
	if err != nil {
		return fmt.Errorf("unable to resolve link parent: %w", err)
	}
	if !isWithin(realParent, realRoot) {
		return fmt.Errorf("symlink parent escapes extraction root")
	}

	resolved := filepath.Join(realParent, target)
	if !isWithin(resolved, realRoot) {
		return fmt.Errorf("symlink target escapes extraction root")
	}
	// the target itself may run through links planted by earlier entries
	if existing, err := filepath.EvalSymlinks(resolved); err == nil && !isWithin(existing, realRoot) {
		return fmt.Errorf("symlink target resolves outside extraction root")
	}

	return os.Symlink(target, destPath)
}

// zipEOCDSignature is the end-of-central-directory record's signature. A zip is defined by this
// record: it is what a reader seeks to in order to find the central directory, which is why a zip
// with something concatenated in front of it still opens.
var zipEOCDSignature = []byte{'P', 'K', 0x05, 0x06}

// maxZipEOCDSearch is how far back the record can be. The EOCD is 22 bytes and ends with a comment
// of up to 65535 bytes, so it starts no earlier than this many bytes from the end.
const maxZipEOCDSearch = 22 + 65535

// zipLocalFileHeaderSignature starts every entry in a zip. In a self-extracting archive the first
// one follows the stub, so it is what a bounded read of the head can find.
var zipLocalFileHeaderSignature = []byte{'P', 'K', 0x03, 0x04}

// MaxAppendedArchiveStubBytes is how far into a file a hidden archive is looked for. A Spring Boot
// launcher stub is about 9 KB, so this is generous by a wide margin; a stub longer than this hides
// its archive from the walk, which is the cost of not reading every candidate to the end.
const MaxAppendedArchiveStubBytes = 64 * 1024

// MayHideAnAppendedArchive reports whether the head of this stream contains a zip local file header,
// and returns a reader that replays what it consumed.
//
// It exists to make the candidate set affordable. A file whose head sniffs as a script, an
// executable, or as nothing recognizable may still be an archive wearing a stub, but almost none of
// them are - and the authoritative test, the end-of-central-directory record, is at the far end of
// the file, so applying it to every such candidate means reading every executable in a scan to its
// end. Measured on a stock ruby image that doubled the scan.
//
// So the head is checked first, cheaply and with a bound, and only a file that shows an entry
// signature there is read in full and put to the real test. This narrows what is examined; it never
// admits anything, because a file that passes here is still refused by the extractor unless it ends
// in a valid central directory.
func MayHideAnAppendedArchive(r io.Reader) (io.Reader, bool) {
	head := make([]byte, MaxAppendedArchiveStubBytes)
	n, err := io.ReadFull(r, head)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return io.MultiReader(bytes.NewReader(head[:n]), r), false
	}
	head = head[:n]
	return io.MultiReader(bytes.NewReader(head), r), bytes.Contains(head, zipLocalFileHeaderSignature)
}

// HasZipEndOfCentralDirectory reports whether the content ends in a zip end-of-central-directory
// record, which is the definition of a zip and the only part of one whose position is knowable
// without parsing.
//
// This is what identifies an archive that content sniffing types by its head: a self-extracting
// archive is a launcher stub with a zip concatenated onto it, so its first bytes are the stub's and
// no magic-at-offset-zero test can see the archive. The record at the end is unambiguous, and
// mholt/archives extracts such a file correctly once it is asked to - it reads through
// archive/zip, which locates the central directory from the end.
//
// It is a content test, so it cannot make a non-archive extractable: a file named `notes.zip` that
// is prose has no such record and is refused here exactly as it is refused by format identification.
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
