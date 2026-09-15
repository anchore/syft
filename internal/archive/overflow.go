package archive

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/mholt/archives"

	"github.com/anchore/syft/internal/log"
)

// tarBlockSize is the tar format's fixed block size. Every header occupies a whole number of blocks
// and every entry's data is padded up to one, which is why the bytes an archive puts on disk are not
// the sum of its entry sizes - see OverflowTar.
const tarBlockSize = 512

// overflowTarName is the basename of the one file an archive's entries are written into. It sits beside
// the archive's logical root rather than inside it, so nothing in the archive's own filesystem can
// name it.
const overflowTarName = "contents.tar"

// OverflowTar is the single file one archive's entries are overflowed into.
//
// The point of the whole shape is that a scan's filesystem cost tracks the number of archives it
// finds rather than the number of entries those archives hold. Expanding every entry as its own file
// makes an archive of a hundred thousand entries a hundred thousand inodes - exhausting inodes on a
// filesystem with bytes to spare, and making cleanup proportional to content as well. One tar per
// archive is one inode per archive, and stereoscope's TarIndex then gives direct access to any entry
// by seek offset, so nothing has to be re-read or re-decompressed to reach the end of it.
//
// It is written by hand rather than through a tar.Writer because tar wants an entry's size in the
// header, before its data, and a size an archive declares is exactly what must not be trusted: both
// tar and zip headers carry a size and a crafted archive is free to lie about it. So each entry's
// header is reserved, its data is copied and charged as it lands, and the header is then written over
// the reservation with the size that actually arrived. The reservation is exact because the header is
// encoded as GNU, whose numeric fields are fixed width - the encoded length of a header therefore
// depends on its name and link target and not at all on its size. That is asserted per entry rather
// than assumed, and an entry whose two encodings disagree is dropped rather than corrupting the tar.
type OverflowTar struct {
	path string
	file *os.File

	// offset is where the next byte written will land, which is also the number of bytes this tar
	// holds. Tracked rather than queried so a header can be written back over its reservation.
	offset int64

	// verbatim records that this tar was copied wholesale from an already-tar-shaped stream rather
	// than assembled entry by entry, in which case it carries the source's own end-of-archive marker
	// and must not be given a second one.
	verbatim bool
}

func newOverflowTar(path string) (*OverflowTar, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("unable to create overflow tar %q: %w", path, err)
	}
	return &OverflowTar{path: path, file: f}, nil
}

// Path is where this tar lives, which is what stereoscope's TarIndex needs: it indexes by seek
// offset and therefore wants a seekable, uncompressed file rather than a stream.
func (s *OverflowTar) Path() string {
	return s.path
}

func (s *OverflowTar) Close() error {
	if s == nil || s.file == nil {
		return nil
	}
	err := s.file.Close()
	s.file = nil
	return err
}

// put charges b to the disk limit and writes it, reporting whether the limit refused it. Nothing is
// written when the charge is refused, so the tar never holds bytes the limiter is not accounting for.
func (s *OverflowTar) put(b []byte, result *ExtractionResult, limits ExtractionLimits) (refused bool, err error) {
	if len(b) == 0 {
		return false, nil
	}
	if !limits.Charge.Disk(int64(len(b))) {
		return true, nil
	}
	n, err := s.file.Write(b)
	s.offset += int64(n)
	result.BytesWritten += int64(n)
	if n < len(b) {
		limits.Charge.RefundDisk(int64(len(b) - n))
	}
	return false, err
}

// AddEntry writes one archive entry into the tar: a header, its data, and the padding that takes the
// entry up to a block boundary.
//
// Directory entries carry no data, so what bounds an archive of a million of them is the disk limit
// charging their headers and padding, which is the only resource they actually consume.
func (s *OverflowTar) AddEntry(f archives.FileInfo, result *ExtractionResult, limits ExtractionLimits) error {
	hdr, ok := entryHeader(f)
	if !ok {
		return nil
	}

	reserved, err := encodeHeader(hdr, 0)
	if err != nil {
		// GNU could not represent this entry; let the tar package pick a format it can, and rely on
		// the length check below to drop the entry if that choice makes the length size-dependent
		hdr.Format = tar.FormatUnknown
		reserved, err = encodeHeader(hdr, 0)
		if err != nil {
			log.WithFields("entry", f.NameInArchive, "error", err).
				Debug("skipping archive entry whose header cannot be encoded")
			return nil
		}
	}

	start := s.offset
	if refused, err := s.put(reserved, result, limits); err != nil {
		return err
	} else if refused {
		return s.dropEntry(start, result, limits)
	}

	written, refused, err := s.copyEntryData(f, hdr, result, limits)
	if err != nil {
		return err
	}
	if refused {
		// this entry would have taken the scan's disk usage past the disk limit. Drop it rather than
		// leaving a silently short one behind: a half-written jar or pom is worse than an absent one,
		// because a cataloger will try to parse it and may believe what it finds.
		return s.dropEntry(start, result, limits)
	}

	final, err := encodeHeader(hdr, written)
	if err != nil || len(final) != len(reserved) {
		// the reservation and the real header disagree on length, so writing the real header would
		// either overwrite the entry's first bytes or leave a gap - either way an unreadable tar.
		// GNU's fixed-width numeric fields make this unreachable in practice; it is checked because
		// the alternative to checking is silent corruption.
		log.WithFields("entry", f.NameInArchive, "error", err).
			Debug("skipping archive entry whose header length depends on its size")
		return s.dropEntry(start, result, limits)
	}
	if _, err := s.file.WriteAt(final, start); err != nil {
		return fmt.Errorf("unable to write header for archive entry %q: %w", f.NameInArchive, err)
	}

	if pad := (tarBlockSize - written%tarBlockSize) % tarBlockSize; pad > 0 {
		if refused, err := s.put(make([]byte, pad), result, limits); err != nil {
			return err
		} else if refused {
			return s.dropEntry(start, result, limits)
		}
	}

	result.FilesExtracted++
	return nil
}

// copyEntryData copies one entry's content into the tar, charging every chunk as it lands, and reports
// how much actually arrived. A size the archive declared is never used: both tar and zip headers carry
// one and a crafted archive is free to lie about it, so the header is written afterwards from what was
// counted here. An entry carrying no data - a directory, a link - copies nothing.
func (s *OverflowTar) copyEntryData(f archives.FileInfo, hdr *tar.Header, result *ExtractionResult, limits ExtractionLimits) (written int64, refused bool, err error) {
	if hdr.Typeflag != tar.TypeReg {
		return 0, false, nil
	}

	src, err := f.Open()
	if err != nil {
		return 0, false, fmt.Errorf("unable to open archive entry %q: %w", f.NameInArchive, err)
	}
	defer func() {
		if closeErr := src.Close(); closeErr != nil {
			log.WithFields("entry", f.NameInArchive, "error", closeErr).Trace("unable to close archive entry")
		}
	}()

	written, refused, err = copyCharged(s.file, src, limits.Charge)
	s.offset += written
	result.BytesWritten += written
	return written, refused, err
}

// dropEntry rewinds the tar to where the entry being written began, refunding what that entry
// charged since those bytes are no longer on disk, and stops the extraction. Whatever was written
// before this entry is a complete, readable tar and is still cataloged; see ExtractionResult.
func (s *OverflowTar) dropEntry(start int64, result *ExtractionResult, limits ExtractionLimits) error {
	spent := s.offset - start
	if err := s.file.Truncate(start); err != nil {
		log.WithFields("path", s.path, "error", err).Trace("unable to rewind overflow tar past an over-limit entry")
	}
	if _, err := s.file.Seek(start, io.SeekStart); err != nil {
		log.WithFields("path", s.path, "error", err).Trace("unable to seek overflow tar past an over-limit entry")
	}
	s.offset = start
	limits.Charge.RefundDisk(spent)
	result.BytesWritten -= spent
	if result.Truncation == "" {
		result.Truncation = TruncatedByDiskLimit
	}
	return errTruncated
}

// CopyVerbatim writes an already-tar-shaped stream into the overflow file as it stands, which is what a
// tar-family archive gets: a compressed tar is decompressed once into a plain tar rather than
// expanded entry by entry, and a plain tar is copied. Charging is per chunk as the bytes land, so a
// decompression bomb is bounded by the disk limit rather than by what the archive claimed.
//
// A refused chunk leaves the tar ending part way through an entry. That is deliberately not repaired
// here: indexing keeps every entry it could read and reports the tail as a truncation, which is the
// same outcome as stopping on a whole-entry boundary and needs no second mechanism.
func (s *OverflowTar) CopyVerbatim(r io.Reader, result *ExtractionResult, limits ExtractionLimits) error {
	s.verbatim = true

	written, refused, err := copyCharged(s.file, r, limits.Charge)
	s.offset += written
	result.BytesWritten += written
	if err != nil {
		return err
	}
	if refused {
		result.Truncation = TruncatedByDiskLimit
		return errTruncated
	}
	return nil
}

// Finish writes the tar's end-of-archive marker.
//
// A marker that does not fit within the disk limit is not an error: Go's tar reader stops at the
// first zero block or at the end of the file, so a tar that simply ends reads exactly the same.
func (s *OverflowTar) Finish(result *ExtractionResult, limits ExtractionLimits) {
	if s.verbatim {
		// the source stream carried its own marker
		return
	}
	if refused, err := s.put(make([]byte, 2*tarBlockSize), result, limits); err != nil || refused {
		log.WithFields("path", s.path, "error", err).Trace("overflow tar written without an end-of-archive marker")
	}
}

// entryHeader builds the tar header for one archive entry, or reports false when the entry is not
// something worth carrying.
//
// Symlinks are recorded as symlink headers rather than being created and checked as real links,
// because writing a header traverses no path: nothing is created, so there is nothing for a crafted
// target to redirect. Where a link points is decided when the archive's filetree is built, inside
// that tree, so a target naming the host filesystem resolves to nothing rather than to the host.
//
// Device nodes, fifos and sockets are skipped, as they were when entries were files: they cannot
// round-trip and no cataloger can read one.
func entryHeader(f archives.FileInfo) (*tar.Header, bool) {
	mode := f.Mode()
	if !mode.IsRegular() && !mode.IsDir() && mode.Type()&fs.ModeSymlink == 0 {
		log.WithFields("entry", f.NameInArchive, "mode", mode).Debug("skipping non-regular archive entry")
		return nil, false
	}

	hdr, err := tar.FileInfoHeader(f.FileInfo, f.LinkTarget)
	if err != nil {
		log.WithFields("entry", f.NameInArchive, "error", err).Debug("skipping archive entry with an unusable header")
		return nil, false
	}

	// the name is carried through as the archive gave it, unsanitized. Nothing is written through it
	// - it is a field in a header - and the one place it can still mislead is the logical filetree,
	// so it is sanitized there, once, rather than in each of the two paths that write a tar.
	hdr.Name = f.NameInArchive
	if f.IsDir() && !strings.HasSuffix(hdr.Name, "/") {
		hdr.Name += "/"
	}
	hdr.Linkname = f.LinkTarget

	// GNU rather than the format the tar package would pick: its numeric fields are fixed width, so
	// the encoded length of a header does not depend on the size recorded in it. That is what lets
	// the header be reserved before the entry's real size is known and written afterwards. Fields GNU
	// cannot carry are cleared instead of forcing the encoder into PAX, where a large size becomes an
	// extra record and the length stops being predictable.
	hdr.Format = tar.FormatGNU
	hdr.PAXRecords = nil
	hdr.Uname, hdr.Gname = "", ""
	hdr.AccessTime, hdr.ChangeTime = time.Time{}, time.Time{}
	hdr.ModTime = hdr.ModTime.Truncate(time.Second)

	return hdr, true
}

// encodeHeader returns the bytes one header occupies in a tar, for the given size. It includes
// whatever the format needs around it - a GNU long-name record for a name a header field cannot
// hold - because all of it is written before the entry's data and all of it has to be reserved.
func encodeHeader(hdr *tar.Header, size int64) ([]byte, error) {
	h := *hdr
	h.Size = size

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	// WriteHeader emits the header, and any record the format needs ahead of it, before it returns.
	// Close is deliberately not called: it would append the end-of-archive marker, which belongs to
	// the tar being assembled and not to one header in it.
	if err := tw.WriteHeader(&h); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// tarStream returns the plain-tar byte stream for a tar-family archive, decompressing once where the
// archive is a compressed tar, and reports false for anything that is not a tar.
//
// This is what makes a compressed tar strictly cheaper than it was: it used to be expanded entry by
// entry into a tree of files, and here it is decompressed once into a file that is already the
// storage format, then indexed by seek offset. A plain tar is copied for the same reason - TarIndex
// needs a seekable uncompressed file, and the archive's own bytes may be held in memory.
func tarStream(format archives.Format, r io.Reader) (io.ReadCloser, bool) {
	switch f := format.(type) {
	case archives.Tar:
		return io.NopCloser(r), true
	case archives.CompressedArchive:
		if !isTarFormat(f) {
			return nil, false
		}
		if f.Compression == nil {
			return io.NopCloser(r), true
		}
		rc, err := f.OpenReader(r)
		if err != nil {
			log.WithFields("error", err).Debug("unable to decompress tar-family archive")
			return nil, false
		}
		return rc, true
	}
	return nil, false
}

// isTarFormat reports whether the archival half of a compressed archive is a tar. Identify sets both
// halves for a compressed tar, so either answers; both are checked because only one is guaranteed to
// be non-nil in general.
func isTarFormat(f archives.CompressedArchive) bool {
	if _, ok := f.Archival.(archives.Tar); ok {
		return true
	}
	_, ok := f.Extraction.(archives.Tar)
	return ok
}
