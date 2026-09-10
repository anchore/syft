package archive

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/log"
)

// copyChunkSize is how much is read, charged and written at a time. It bounds how far a charge can
// be ahead of what has actually been written, and matches io.Copy's own buffer size.
const copyChunkSize = 32 * 1024

// ReaderAtSeeker is the random access an archive format needs. A zip reads its central directory
// from the end of the stream, so a plain io.Reader will not do; both a *bytes.Reader over content
// held in memory and an *os.File over content overflowed to disk satisfy it.
type ReaderAtSeeker interface {
	io.Reader
	io.ReaderAt
	io.Seeker
}

// Content is one archive's bytes, wherever the limiter routed them.
//
// Name is the archive's file name and is used for format identification only - never to open
// anything - so content held in memory needs no file on disk at all.
type Content struct {
	Name   string
	Reader ReaderAtSeeker

	// closer releases the overflow file's handle; nil for content held in memory.
	closer io.Closer
}

// Close releases the handle on overflow content. It is a no-op for content held in memory.
func (c Content) Close() error {
	if c.closer == nil {
		return nil
	}
	return c.closer.Close()
}

// OpenFileContent opens an archive already on disk as Content. The caller closes it.
func OpenFileContent(path string) (Content, error) {
	f, err := os.Open(path)
	if err != nil {
		return Content{}, err
	}
	return Content{Name: filepath.Base(path), Reader: f, closer: f}, nil
}

// holdContent routes one archive's bytes: held in memory and charged to the memory limit while that
// limit admits them, overflowed into workDir and charged to the disk limit once it does not. Where the
// boundary falls is decided entirely by the memory limit - there is no separate configured size at
// which overflowing begins.
//
// Content is read and charged incrementally, copyChunkSize at a time, rather than read speculatively
// into a buffer ahead of any charge: nothing is ever held beyond what the memory limit would admit at
// that moment, so a single archive far larger than the limit is never buffered past it. A zero
// memory limit refuses every chunk, so its content overflows to disk in full; a negative memory limit
// never refuses, so nothing overflows for want of memory.
//
// When the limit refuses a chunk part way through, what has already been read leads the overflow rather
// than being re-read from the start or lost, and the memory it was charged against is refunded since
// it is about to be charged to disk instead.
//
// Memory pressure degrades to disk - content that would take memory in use past the memory limit
// overflows instead of being refused, because there is somewhere for it to go. The disk limit is
// terminal: there is nowhere further, so content that would take it past the disk limit yields
// ErrDiskLimitReached and the archive is skipped. Nothing waits for capacity; see ExtractToResolver.
func holdContent(r io.Reader, workDir, name string, charge *Charge, notify Notify) (Content, error) {
	var held bytes.Buffer
	chunk := make([]byte, copyChunkSize)
	for {
		n, readErr := r.Read(chunk)
		if n > 0 {
			if !charge.Memory(int64(n)) {
				// the memory limit refused this chunk: overflow what is already held plus this chunk
				// plus whatever remains, without re-reading from the start
				if notify != nil {
					notify(ContentOverflowed{Archive: name, Bytes: int64(held.Len() + n), Reason: overflowReason(charge)})
				}
				charge.RefundMemory(int64(held.Len()))
				return overflowContent(io.MultiReader(&held, bytes.NewReader(chunk[:n]), r), workDir, name, charge)
			}
			held.Write(chunk[:n])
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return Content{Name: name, Reader: bytes.NewReader(held.Bytes())}, nil
			}
			return Content{}, fmt.Errorf("unable to read archive content: %w", readErr)
		}
	}
}

// overflowContent writes an archive's bytes into workDir, charging the disk limit as they land, and
// returns a reader over the file positioned at its start.
//
// This is the only filesystem write left in the extraction path - an archive's entries are headers in
// one tar and traverse no path - and the name it writes under is derived from where the archive was
// found, which inside another archive is text the archive supplied. So the destination is checked the
// same two ways an entry's path used to be: lexically, and then against where it really lands on the
// filesystem.
func overflowContent(r io.Reader, workDir, name string, charge *Charge) (Content, error) {
	dest, err := intFile.SafeJoin(workDir, name)
	if err != nil {
		return Content{}, fmt.Errorf("refusing to overflow archive content to %q: %w", name, err)
	}
	if inside, err := resolvesInsideRoot(workDir, dest); err != nil || !inside {
		return Content{}, fmt.Errorf("refusing to overflow archive content outside its work directory: %q", name)
	}
	f, err := os.OpenFile(dest, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return Content{}, fmt.Errorf("unable to create temp archive file: %w", err)
	}

	written, limitReached, err := copyCharged(f, r, charge)
	if err == nil && limitReached {
		err = ErrDiskLimitReached
	}
	if err == nil {
		_, err = f.Seek(0, io.SeekStart)
	}
	if err != nil {
		charge.RefundDisk(written)
		if closeErr := f.Close(); closeErr != nil {
			log.WithFields("path", dest, "error", closeErr).Trace("unable to close overflow archive file")
		}
		if rmErr := os.Remove(dest); rmErr != nil {
			log.WithFields("path", dest, "error", rmErr).Trace("unable to remove overflow archive file")
		}
		if errors.Is(err, ErrDiskLimitReached) {
			return Content{}, err
		}
		return Content{}, fmt.Errorf("unable to write temp archive file: %w", err)
	}

	return Content{Name: name, Reader: f, closer: f}, nil
}

// copyCharged copies src into dst, charging every chunk to the disk limit before it is written, so
// what bounds the copy is what actually lands rather than any size the archive declared. It stops at
// the first refused charge and says so, leaving the caller to decide whether that truncates one
// entry or skips a whole archive.
func copyCharged(dst io.Writer, src io.Reader, charge *Charge) (written int64, limitReached bool, err error) {
	buf := make([]byte, copyChunkSize)
	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			if !charge.Disk(int64(n)) {
				return written, true, nil
			}
			w, writeErr := dst.Write(buf[:n])
			written += int64(w)
			if w < n {
				charge.RefundDisk(int64(n - w))
			}
			if writeErr != nil {
				return written, false, writeErr
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return written, false, nil
			}
			return written, false, readErr
		}
	}
}
