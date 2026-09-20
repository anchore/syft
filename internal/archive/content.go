package archive

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/log"
)

// copyChunkSize is the read/charge/write chunk size, bounding how far a charge runs ahead of what is
// written. Matches io.Copy's buffer size.
const copyChunkSize = 32 * 1024

// ReaderAtSeeker is the random access an archive format needs: a zip reads its central directory from
// the end of the stream, so a plain io.Reader will not do.
type ReaderAtSeeker interface {
	io.Reader
	io.ReaderAt
	io.Seeker
}

// Content is one archive's bytes, wherever the limiter routed them.
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

// holdContent holds one archive's bytes in memory while the memory limit admits them, and spills into
// workDir against the disk limit once it does not. Reads and charges copyChunkSize at a time so an
// oversized archive is never held past the limit. A zero memory limit spills in full; a negative one
// never refuses.
//
// On a refused chunk, held bytes and the rest of the stream spill without re-reading, and the memory
// charge is refunded as it is charged to disk. The disk limit is terminal: exceeding it yields
// ErrDiskLimitReached and the archive is skipped (see ExtractToResolver).
func holdContent(r io.Reader, workDir *WorkDir, name string, charge *Charge, notify Notify) (Content, error) {
	var held bytes.Buffer
	chunk := make([]byte, copyChunkSize)
	for {
		n, readErr := r.Read(chunk)
		if n > 0 {
			if !charge.Memory(int64(n)) {
				// spill held bytes, this chunk, and the rest without re-reading
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

// overflowContent writes an archive's bytes into its work directory, charging the disk limit as they
// land, and returns a reader over the file positioned at its start. The work directory is created
// here on first write, so an in-memory archive never creates one.
//
// This is the only filesystem write in the extraction path, and the name derives from where the
// archive was found - attacker-controlled inside another archive - so the destination is checked
// both lexically and against where it really lands.
func overflowContent(r io.Reader, workDir *WorkDir, name string, charge *Charge) (Content, error) {
	dir, err := workDir.Path()
	if err != nil {
		return Content{}, err
	}

	dest, err := intFile.SafeJoin(dir, name)
	if err != nil {
		return Content{}, fmt.Errorf("refusing to overflow archive content to %q: %w", name, err)
	}
	if inside, err := resolvesInsideRoot(dir, dest); err != nil || !inside {
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

// copyCharged copies src into dst, charging each chunk to the disk limit before writing, so the copy
// is bounded by what lands rather than any declared size. It stops at the first refused charge and
// reports it; the caller decides whether that truncates one entry or skips the archive.
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
