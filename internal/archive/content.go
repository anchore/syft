package archive

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/anchore/syft/internal/log"
)

// copyChunkSize is how many bytes are read and charged at a time, bounding how far a charge runs
// ahead of what is actually held.
const copyChunkSize = 32 * 1024

// ReaderAtSeeker is the random access an archive format needs: a zip is read from its central
// directory at the end of the stream.
type ReaderAtSeeker interface {
	io.Reader
	io.ReaderAt
	io.Seeker
}

// Content is one archive's bytes, ready for random access.
type Content struct {
	ReaderAtSeeker

	// release gives back what holding the bytes cost; nil when they are read in place
	release func()
}

// Release drops the held bytes and refunds their charge. Safe to call more than once.
func (c *Content) Release() {
	if c.release != nil {
		c.release()
		c.release = nil
	}
}

// acquireContent makes an archive's bytes random-access. Bytes that already are, such as a file on
// disk or an entry of a parent archive, are read in place and cost nothing. Anything else is held
// in memory or written to disk within the limits.
func acquireContent(r io.Reader, name string, workDir *WorkDir, charge *Charge) (Content, error) {
	if ras, ok := r.(ReaderAtSeeker); ok {
		return Content{ReaderAtSeeker: ras}, nil
	}
	return holdContent(r, name, workDir, charge)
}

// holdContent holds an archive's bytes in memory while the memory limit admits them and writes them
// to disk once it does not. Reaching the disk limit yields ErrDiskLimitReached.
func holdContent(r io.Reader, name string, workDir *WorkDir, charge *Charge) (Content, error) {
	held, rest, err := readWhileMemoryAdmits(r, charge)
	if err != nil {
		return Content{}, fmt.Errorf("unable to read archive content: %w", err)
	}
	if rest == nil {
		return Content{
			ReaderAtSeeker: bytes.NewReader(held),
			release:        func() { charge.RefundMemory(int64(len(held))) },
		}, nil
	}

	log.WithFields("archive", name).Debug("archive content does not fit in memory; writing it to disk")
	charge.RefundMemory(int64(len(held)))
	return writeContentToDisk(io.MultiReader(bytes.NewReader(held), rest), workDir, charge)
}

// readWhileMemoryAdmits reads r into memory, charging each chunk before holding it so a stream larger
// than the memory limit is never held in full. When a chunk is refused it returns what is held so
// far, still charged, and a reader over the refused chunk followed by the rest of r. rest is nil when
// all of r fit.
func readWhileMemoryAdmits(r io.Reader, charge *Charge) (held []byte, rest io.Reader, err error) {
	chunk := make([]byte, copyChunkSize)
	for {
		n, readErr := r.Read(chunk)
		if n > 0 {
			if !charge.Memory(int64(n)) {
				return held, io.MultiReader(bytes.NewReader(chunk[:n]), r), nil
			}
			held = append(held, chunk[:n]...)
		}
		if errors.Is(readErr, io.EOF) {
			return held, nil, nil
		}
		if readErr != nil {
			return nil, nil, readErr
		}
	}
}

// contentFileName is the file an archive's own bytes are written to when they do not fit in memory.
const contentFileName = "archive"

// writeContentToDisk writes r into the work directory, charging the disk limit as bytes land, and
// returns a reader over the file. Reaching the disk limit removes the file and yields
// ErrDiskLimitReached.
func writeContentToDisk(r io.Reader, workDir *WorkDir, charge *Charge) (Content, error) {
	dir, err := workDir.Path()
	if err != nil {
		return Content{}, err
	}
	path := filepath.Join(dir, contentFileName)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return Content{}, fmt.Errorf("unable to create archive content file: %w", err)
	}

	written, err := copyCharged(f, r, charge)
	release := func() {
		charge.RefundDisk(written)
		if err := f.Close(); err != nil {
			log.WithFields("path", path, "error", err).Trace("unable to close archive content file")
		}
		if err := os.Remove(path); err != nil {
			log.WithFields("path", path, "error", err).Trace("unable to remove archive content file")
		}
	}
	if err == nil {
		_, err = f.Seek(0, io.SeekStart)
	}
	if err != nil {
		release()
		if errors.Is(err, ErrDiskLimitReached) {
			return Content{}, err
		}
		return Content{}, fmt.Errorf("unable to write archive content file: %w", err)
	}
	return Content{ReaderAtSeeker: f, release: release}, nil
}

// copyCharged copies src to dst, charging each chunk to the disk limit before writing it. It stops
// with ErrDiskLimitReached at the first refused chunk; bytes written before that stay charged.
func copyCharged(dst io.Writer, src io.Reader, charge *Charge) (written int64, err error) {
	chunk := make([]byte, copyChunkSize)
	for {
		n, readErr := src.Read(chunk)
		if n > 0 {
			if !charge.Disk(int64(n)) {
				return written, ErrDiskLimitReached
			}
			w, writeErr := dst.Write(chunk[:n])
			written += int64(w)
			charge.RefundDisk(int64(n - w))
			if writeErr != nil {
				return written, writeErr
			}
		}
		if errors.Is(readErr, io.EOF) {
			return written, nil
		}
		if readErr != nil {
			return written, readErr
		}
	}
}
