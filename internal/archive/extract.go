package archive

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/mholt/archives"

	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
)

// Extracted is one archive opened as its own filesystem.
type Extracted struct {
	// Resolver reads the archive's entries. Its locations carry the archive's FileSystemID and
	// ArchivePath.
	Resolver file.Resolver

	// Digests are of the archive file itself.
	Digests []file.Digest

	// Truncated reports that the disk limit stopped extraction early. Resolver covers the entries
	// stored before that.
	Truncated bool

	cleanup func()
}

// Cleanup removes everything the archive holds on disk and releases its charge against the limiter.
// Safe to call more than once.
func (e *Extracted) Cleanup() {
	if e == nil || e.cleanup == nil {
		return
	}
	e.cleanup()
	e.cleanup = nil
}

// Extract opens the archive read from r as its own filesystem, holding its bytes and entries within
// the limiter's bounds. It returns nil when the content is not an archive it can read, and
// ErrDiskLimitReached when the archive's own bytes cannot be placed within the disk limit. The caller
// must Cleanup the result.
//
// fileSystemID and archivePath are stamped onto every location the resolver returns: the filesystem
// the archive was found on, and the colon-delimited chain of archives from the scan root to this one.
func Extract(ctx context.Context, r io.Reader, fileSystemID, archivePath string, limiter *Limiter, exclusions Exclusions) (*Extracted, error) {
	workDir := NewWorkDir(ctx)
	charge := limiter.Charge()
	store := NewEntryStore(archivePath, workDir, charge)
	var content Content
	release := func() {
		content.Release()
		if err := store.Close(); err != nil {
			log.WithFields("archive", archivePath, "error", err).Trace("unable to close archive entries file")
		}
		workDir.Remove()
		charge.Release()
	}

	content, err := acquireContent(r, archivePath, workDir, charge)
	if err != nil {
		release()
		return nil, err
	}
	// the archive's own bytes are needed only until they are extracted and digested
	defer content.Release()

	format := identifyFormat(ctx, archiveFileName(archivePath), content)
	if format == nil {
		release()
		return nil, nil
	}

	truncated, err := extractInto(ctx, format, content, store, exclusions)
	if err != nil {
		release()
		return nil, fmt.Errorf("unable to extract archive %q: %w", archivePath, err)
	}

	return &Extracted{
		Resolver:  NewIndex(store, fileSystemID, archivePath),
		Digests:   digestsOf(ctx, content, archivePath),
		Truncated: truncated,
		cleanup:   release,
	}, nil
}

// archiveFileName returns the archive's own file name from the end of its archive path, which format
// identification reads for its extension.
func archiveFileName(archivePath string) string {
	return path.Base(archivePath[strings.LastIndexByte(archivePath, ':')+1:])
}

// identifyFormat returns the format able to extract this content, or nil when it is not an archive.
//
// Identification from the head of the stream wins: a tar holding one jar ends in that jar's central
// directory, and reading the tar as a zip would lose the rest. The end of the stream is consulted
// only when the head identifies nothing, which is how a zip appended to a launcher script (a Spring
// Boot executable jar) is found.
func identifyFormat(ctx context.Context, name string, content ReaderAtSeeker) archives.Extractor {
	if _, err := content.Seek(0, io.SeekStart); err != nil {
		return nil
	}
	format, _, err := intFile.IdentifyArchive(ctx, name, content)
	if err == nil {
		// a bare compression format, such as a gzipped file that is not a tar, is not extractable
		extractor, _ := format.(archives.Extractor)
		return extractor
	}
	if HasZipEndOfCentralDirectory(content) {
		return archives.Zip{}
	}
	return nil
}

// extractInto reads every entry of the archive into the store. Reaching the disk limit stops the
// walk and reports truncation rather than an error.
func extractInto(ctx context.Context, format archives.Extractor, content ReaderAtSeeker, store *EntryStore, exclusions Exclusions) (truncated bool, err error) {
	if _, err := content.Seek(0, io.SeekStart); err != nil {
		return false, err
	}
	err = format.Extract(ctx, content, func(_ context.Context, f archives.FileInfo) error {
		hdr, ok := entryHeader(f)
		if !ok || exclusions.Excludes(hdr.Name) {
			return nil
		}
		return storeEntry(store, hdr, f)
	})
	if errors.Is(err, ErrDiskLimitReached) {
		return true, nil
	}
	return false, err
}

func storeEntry(store *EntryStore, hdr tar.Header, f archives.FileInfo) error {
	if !f.Mode().IsRegular() {
		return store.Add(hdr, nil)
	}
	content, err := f.Open()
	if err != nil {
		log.WithFields("entry", hdr.Name, "error", err).Trace("unable to open archive entry, skipping it")
		return nil
	}
	defer func() {
		if err := content.Close(); err != nil {
			log.WithFields("entry", hdr.Name, "error", err).Trace("unable to close archive entry")
		}
	}()
	return store.Add(hdr, content)
}

// archiveDigestHashes are the digests taken of an archive as a whole: SHA-1, matching what the java
// cataloger reports for a jar.
var archiveDigestHashes = []crypto.Hash{crypto.SHA1}

// digestsOf digests the archive's own bytes while they are in hand. A failure is logged and returns
// nothing rather than discarding an archive that extracted fine.
func digestsOf(ctx context.Context, content ReaderAtSeeker, archivePath string) []file.Digest {
	if _, err := content.Seek(0, io.SeekStart); err != nil {
		log.WithFields("archive", archivePath, "error", err).Trace("unable to rewind archive content for digests")
		return nil
	}
	digests, err := intFile.NewDigestsFromFile(ctx, io.NopCloser(content), archiveDigestHashes)
	if err != nil {
		log.WithFields("archive", archivePath, "error", err).Trace("unable to digest archive")
		return nil
	}
	return digests
}

var (
	// zipLocalFileHeaderSignature starts every entry in a zip.
	zipLocalFileHeaderSignature = []byte{'P', 'K', 0x03, 0x04}

	// zipEOCDSignature starts the end-of-central-directory record that closes every zip. Readers
	// locate the central directory from it, which is why a zip with data prepended still opens.
	zipEOCDSignature = []byte{'P', 'K', 0x05, 0x06}
)

const (
	// maxAppendedArchiveStubBytes is how far into a file an appended zip's first entry is looked for. A
	// Spring Boot launcher stub is about 9 KB.
	maxAppendedArchiveStubBytes = 64 * 1024

	// maxZipEOCDSearch is how far from the end the end-of-central-directory record can start: the 22
	// byte record plus a comment of up to 65535 bytes.
	maxZipEOCDSearch = 22 + 65535
)

// MayHideAnAppendedArchive reports whether a zip entry signature appears in the head of the stream,
// which a zip appended to a launcher stub does and a file that merely has an archive's extension
// almost never does. The returned reader replays what was consumed.
func MayHideAnAppendedArchive(r io.Reader) (io.Reader, bool) {
	head := make([]byte, maxAppendedArchiveStubBytes)
	n, err := io.ReadFull(r, head)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return r, false
	}
	head = head[:n]
	found := bytes.Contains(head, zipLocalFileHeaderSignature)

	if seeker, ok := r.(io.Seeker); ok {
		if _, err := seeker.Seek(0, io.SeekStart); err == nil {
			return r, found
		}
	}
	return io.MultiReader(bytes.NewReader(head), r), found
}

// HasZipEndOfCentralDirectory reports whether the content ends in a zip end-of-central-directory
// record, the one part of a zip whose position is known without parsing it.
func HasZipEndOfCentralDirectory(r ReaderAtSeeker) bool {
	size, err := r.Seek(0, io.SeekEnd)
	if err != nil || size < int64(len(zipEOCDSignature)) {
		return false
	}
	window := min(size, int64(maxZipEOCDSearch))
	buf := make([]byte, window)
	if _, err := r.ReadAt(buf, size-window); err != nil && !errors.Is(err, io.EOF) {
		return false
	}
	return bytes.Contains(buf, zipEOCDSignature)
}
