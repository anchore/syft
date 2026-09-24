package archive

import (
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

// Extract opens the archive read from r as its own filesystem, holding its bytes and entries within
// the limiter's bounds. It returns nil when the content is not an archive it can read, and
// ErrDiskLimitReached when the archive's own bytes cannot be placed within the disk limit. The caller
// must Cleanup the result.
//
// fileSystemID and archivePath are stamped onto every location the resolver returns: the filesystem
// the archive was found on, and the colon-delimited chain of archives from the scan root to this one.
func Extract(ctx context.Context, r io.Reader, fileSystemID, archivePath string, limiter *Limiter, exclusions Exclusions) (*Resolver, error) {
	charge := limiter.charge()
	resolver := newResolver(ctx, fileSystemID, archivePath, charge)

	// deferred so that a panic in a decoder still gives back the charge and removes any spill file
	succeeded := false
	defer func() {
		if !succeeded {
			resolver.Cleanup()
		}
	}()

	content, release, err := resolver.acquire(r)
	if err != nil {
		return nil, err
	}
	// the archive's own bytes are needed only until they are extracted and digested
	defer release()

	format := identifyFormat(ctx, archiveFileName(archivePath), content)
	if format == nil {
		return nil, nil
	}

	if err := resolver.extract(ctx, format, content, exclusions); err != nil {
		return nil, fmt.Errorf("unable to extract archive %q: %w", archivePath, err)
	}
	resolver.Digests = digestsOf(ctx, content, archivePath)
	succeeded = true
	return resolver, nil
}

// acquire makes the archive's own bytes random-access, which identifying, extracting and digesting
// them needs. Bytes that already are, such as a file on disk or an entry of a parent archive, are
// read in place and cost nothing. Anything else is held within the limits like an entry, and the
// returned release gives back what memory it takes; bytes spilled to disk stay until Cleanup.
// Reaching the disk limit yields ErrDiskLimitReached.
func (r *Resolver) acquire(content io.Reader) (ReaderAtSeeker, func(), error) {
	if ras, ok := content.(ReaderAtSeeker); ok {
		return ras, func() {}, nil
	}
	var b blob
	if err := r.put(&b, content); err != nil {
		if errors.Is(err, ErrDiskLimitReached) {
			return nil, nil, err
		}
		return nil, nil, fmt.Errorf("unable to read archive content: %w", err)
	}
	return r.open(&b), func() { r.discard(&b) }, nil
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
// only when the head identifies nothing supported, which is how a zip appended to a launcher script (a
// Spring Boot executable jar) is found, and how a java resource adapter (a zip named .rar) is read.
func identifyFormat(ctx context.Context, name string, content ReaderAtSeeker) archives.Extractor {
	if _, err := content.Seek(0, io.SeekStart); err != nil {
		return nil
	}
	format, _, err := intFile.IdentifyArchive(ctx, name, content)
	if err == nil {
		if extractor := supportedExtractor(format); extractor != nil {
			return extractor
		}
	}
	if HasZipEndOfCentralDirectory(content) {
		return archives.Zip{}
	}
	return nil
}

// supportedExtractor admits only the zip and tar families, the tar family optionally compressed. Other
// formats mholt identifies, such as 7z and rar, pull in decoders that have not been exercised against
// untrusted input here, so they are not opened until they are deliberately supported. A bare
// compression format, such as a gzipped file that is not a tar, is not extractable either.
func supportedExtractor(format archives.Format) archives.Extractor {
	switch f := format.(type) {
	case archives.Zip:
		return f
	case archives.Tar:
		return f
	case archives.CompressedArchive:
		if _, ok := f.Extraction.(archives.Tar); ok {
			return f
		}
	}
	return nil
}

// extract adds every entry of the archive. Reaching the disk limit stops the walk and marks the
// resolver truncated rather than failing.
func (r *Resolver) extract(ctx context.Context, format archives.Extractor, content ReaderAtSeeker, exclusions Exclusions) error {
	if _, err := content.Seek(0, io.SeekStart); err != nil {
		return err
	}
	err := format.Extract(ctx, content, func(_ context.Context, f archives.FileInfo) error {
		hdr, ok := entryHeader(f)
		if !ok || exclusions.Excludes(hdr.Name) {
			return nil
		}
		if !f.Mode().IsRegular() {
			return r.add(hdr, nil)
		}
		entry, err := f.Open()
		if err != nil {
			log.WithFields("entry", hdr.Name, "error", err).Trace("unable to open archive entry, skipping it")
			return nil
		}
		defer func() {
			if err := entry.Close(); err != nil {
				log.WithFields("entry", hdr.Name, "error", err).Trace("unable to close archive entry")
			}
		}()
		return r.add(hdr, entry)
	})
	r.finish()
	if errors.Is(err, ErrDiskLimitReached) {
		r.truncate("extraction stopped at the configured memory or disk limit")
		return nil
	}
	if errors.Is(err, errBudgetSpent) {
		r.truncate("extraction stopped: the archive and those nested in it decompressed to far more than its size (possible decompression bomb)")
		return nil
	}
	if err != nil && ctx.Err() == nil && len(r.files) > 0 {
		// the stream broke partway (a truncated .tar.gz); what was read before that is still good
		r.truncate(fmt.Sprintf("extraction stopped early: %v", err))
		return nil
	}
	return err
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
