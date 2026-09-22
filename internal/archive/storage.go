package archive

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/anchore/syft/internal/log"
)

// copyChunkSize is how many bytes are read and charged at a time, bounding how far a charge runs
// ahead of what is actually held.
const copyChunkSize = 32 * 1024

// spillFilePattern names the one file an archive's content spills into, as in os.CreateTemp.
const spillFilePattern = "archive-spill-*"

// ReaderAtSeeker is the random access an archive format needs: a zip is read from its central
// directory at the end of the stream.
type ReaderAtSeeker interface {
	io.Reader
	io.ReaderAt
	io.Seeker
}

// blob is one piece of content the resolver holds: in memory, or at an offset in its spill file once
// memory refused it. Moving changes nothing that points at the blob.
type blob struct {
	mem  []byte // content while held in memory
	off  int64  // where content starts in the spill file once written there
	size int64
}

// put reads content in full into b, since archive readers are sequential. Each chunk is charged before it
// is held, so a stream larger than the memory limit is never held in full. Reaching the disk limit
// returns ErrDiskLimitReached; what landed in the file before that stays there and stays charged.
func (r *Resolver) put(b *blob, content io.Reader) error {
	if r.chunk == nil {
		r.chunk = make([]byte, copyChunkSize)
	}
	for {
		n, readErr := content.Read(r.chunk)
		if n > 0 {
			if err := r.write(b, r.chunk[:n]); err != nil {
				return err
			}
		}
		if readErr == nil {
			continue
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		return readErr
	}
	return nil
}

// write appends p to b: into memory while the memory limit admits it, otherwise into the spill file
// after everything held in memory is moved there first.
func (r *Resolver) write(b *blob, p []byte) error {
	n := int64(len(p))
	onDisk := b.mem == nil && b.size > 0
	if !onDisk {
		if r.charge.memory(n) {
			if b.mem == nil {
				r.held = append(r.held, b)
			}
			b.mem = append(b.mem, p...)
			b.size += n
			return nil
		}
		if err := r.spill(); err != nil {
			return err
		}
	}

	if err := r.openFile(); err != nil {
		return err
	}
	if !r.charge.disk(n) {
		return ErrDiskLimitReached
	}
	if b.size == 0 {
		b.off = r.written
	}
	// b is always the blob most recently written, so it ends where the file does
	w, err := r.file.WriteAt(p, r.written)
	r.written += int64(w)
	b.size += int64(w)
	r.charge.refundDisk(n - int64(w))
	if err != nil {
		return fmt.Errorf("unable to write archive content to disk: %w", err)
	}
	return nil
}

// spill moves every blob held in memory into the spill file, charging the disk limit as bytes land
// and refunding the memory they leave.
func (r *Resolver) spill() error {
	if len(r.held) == 0 {
		return nil
	}
	if err := r.openFile(); err != nil {
		return err
	}
	log.WithFields("archive", r.archivePath, "held", len(r.held), "bytes", r.written).
		Debug("archive content does not fit in memory; writing it to disk")

	for len(r.held) > 0 {
		b := r.held[0]
		n := int64(len(b.mem))
		if !r.charge.disk(n) {
			return ErrDiskLimitReached
		}
		if _, err := r.file.WriteAt(b.mem, r.written); err != nil {
			return fmt.Errorf("unable to write archive content to disk: %w", err)
		}
		b.off, b.mem = r.written, nil
		r.written += n
		r.charge.refundMemory(n)
		r.held = r.held[1:]
	}
	return nil
}

func (r *Resolver) openFile() error {
	if r.file != nil {
		return nil
	}
	var err error
	if r.tempDir != nil {
		r.file, r.remove, err = r.tempDir.NewFile(spillFilePattern)
	} else {
		r.file, err = os.CreateTemp("", spillFilePattern)
		r.remove = func() {
			if err := os.Remove(r.file.Name()); err != nil {
				log.WithFields("path", r.file.Name(), "error", err).Trace("unable to remove archive temp file")
			}
		}
	}
	if err != nil {
		return fmt.Errorf("unable to create archive temp file: %w", err)
	}
	return nil
}

// discard drops a blob's bytes held in memory and refunds them. Bytes it holds on disk stay until
// Cleanup.
func (r *Resolver) discard(b *blob) {
	for i, held := range r.held {
		if held == b {
			r.held = append(r.held[:i], r.held[i+1:]...)
			break
		}
	}
	r.charge.refundMemory(int64(len(b.mem)))
	b.mem, b.size = nil, 0
}

// open returns a reader over a blob's content, wherever it is. The reader supports Read, Seek and
// ReadAt, so a nested archive can be read where it lies.
func (r *Resolver) open(b *blob) ReaderAtSeeker {
	switch {
	case b.mem != nil:
		return bytes.NewReader(b.mem)
	case b.size == 0:
		return bytes.NewReader(nil)
	default:
		return io.NewSectionReader(r.file, b.off, b.size)
	}
}

// releaseStorage refunds every blob held in memory and closes, removes and refunds the spill file.
// Readers from open must not be used after this. Safe to call more than once.
func (r *Resolver) releaseStorage() {
	for _, b := range r.held {
		r.charge.refundMemory(int64(len(b.mem)))
		b.mem = nil
	}
	r.held = nil
	if r.file == nil {
		return
	}
	if err := r.file.Close(); err != nil {
		log.WithFields("archive", r.archivePath, "error", err).Trace("unable to close archive temp file")
	}
	r.remove()
	r.charge.refundDisk(r.written)
	r.file, r.remove, r.written = nil, nil, 0
}
