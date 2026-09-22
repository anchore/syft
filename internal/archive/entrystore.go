package archive

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/anchore/syft/internal/log"
)

// approxIndexBytesPerEntry estimates what holding one entry costs beyond its content: the entry and
// header themselves, and the index node, path map slot and name index slot the resolver builds over
// it. It is charged so an archive of many tiny entries is still bounded by the limits.
const approxIndexBytesPerEntry = 2 * 1024

func approxIndexBytes(hdr tar.Header) int64 {
	return approxIndexBytesPerEntry + int64(len(hdr.Name)+len(hdr.Linkname))
}

// entriesFileName is the single file an archive's entries overflow into. Entries are located by
// offset; the file has no framing of its own.
const entriesFileName = "entries"

// EntryStore holds one archive's entries: in memory while the memory limit admits them, and in one
// overflow file once it does not. Everything held is charged to one Charge.
type EntryStore struct {
	name    string
	workDir *WorkDir
	charge  *Charge

	entries []*Entry
	file    *os.File
	written int64
}

// NewEntryStore returns an empty store for the named archive that overflows into workDir.
func NewEntryStore(name string, workDir *WorkDir, charge *Charge) *EntryStore {
	return &EntryStore{name: name, workDir: workDir, charge: charge}
}

// Add stores one entry, reading its content in full now since archive readers are sequential.
// Reaching the disk limit stores nothing for this entry and returns ErrDiskLimitReached; entries
// stored before it remain usable.
func (s *EntryStore) Add(hdr tar.Header, content io.Reader) error {
	if !s.charge.Index(approxIndexBytes(hdr)) {
		return ErrDiskLimitReached
	}

	entry := &Entry{Header: hdr}
	if hdr.Typeflag == tar.TypeReg && content != nil {
		held, rest, err := readWhileMemoryAdmits(content, s.charge)
		if err != nil {
			return fmt.Errorf("unable to read archive entry %q: %w", hdr.Name, err)
		}
		entry.mem, entry.size = held, int64(len(held))
		if rest != nil {
			if err := s.overflow(entry, rest); err != nil {
				return err
			}
		}
	}

	s.entries = append(s.entries, entry)
	return nil
}

// overflow writes every entry held in memory into the overflow file, followed by the new entry's held
// bytes and the rest of its content, charging the disk limit as bytes land and refunding the memory
// they leave.
func (s *EntryStore) overflow(entry *Entry, rest io.Reader) error {
	if err := s.openFile(); err != nil {
		return err
	}

	moved := 0
	for _, held := range s.entries {
		if held.mem == nil {
			continue
		}
		if err := s.moveToDisk(held); err != nil {
			return err
		}
		moved++
	}

	if err := s.moveToDisk(entry); err != nil {
		return err
	}
	written, err := copyCharged(io.NewOffsetWriter(s.file, s.written), rest, s.charge)
	s.written += written
	entry.size += written

	log.WithFields("archive", s.name, "entries", moved+1, "bytes", s.written).
		Debug("archive entries do not fit in memory; written to disk")

	if err != nil && !errors.Is(err, ErrDiskLimitReached) {
		return fmt.Errorf("unable to write archive entry %q to disk: %w", entry.Header.Name, err)
	}
	return err
}

func (s *EntryStore) openFile() error {
	if s.file != nil {
		return nil
	}
	dir, err := s.workDir.Path()
	if err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, entriesFileName), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("unable to create archive entries file: %w", err)
	}
	s.file = f
	return nil
}

// moveToDisk appends an entry's in-memory content to the overflow file and points the entry there.
func (s *EntryStore) moveToDisk(entry *Entry) error {
	n := int64(len(entry.mem))
	if !s.charge.Disk(n) {
		return ErrDiskLimitReached
	}
	if _, err := s.file.WriteAt(entry.mem, s.written); err != nil {
		return fmt.Errorf("unable to write archive entry %q to disk: %w", entry.Header.Name, err)
	}
	entry.offset, entry.size = s.written, n
	s.written += n
	s.charge.RefundMemory(n)
	entry.mem = nil
	return nil
}

// Entries returns the stored entries in the order they were added.
func (s *EntryStore) Entries() []*Entry {
	return s.entries
}

// Open returns a reader over an entry's content, wherever it is. The reader supports Read, Seek and
// ReadAt, so a nested archive can be read where it lies.
func (s *EntryStore) Open(entry *Entry) ReaderAtSeeker {
	switch {
	case entry.mem != nil:
		return bytes.NewReader(entry.mem)
	case entry.size == 0:
		return bytes.NewReader(nil)
	default:
		return io.NewSectionReader(s.file, entry.offset, entry.size)
	}
}

// OnDisk reports how many bytes of entry content have been written to the overflow file.
func (s *EntryStore) OnDisk() int64 {
	return s.written
}

// Close releases the overflow file. Readers from Open must not be used after this.
func (s *EntryStore) Close() error {
	if s.file == nil {
		return nil
	}
	err := s.file.Close()
	s.file = nil
	return err
}
