package archive

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sync"

	"github.com/mholt/archives"

	"github.com/anchore/syft/internal/log"
)

// Entry is one archive entry: its header and a reference to its bytes. The bytes move, the entry does
// not, so an index built over these entries stays valid when content spills to disk.
type Entry struct {
	Header tar.Header

	// ref locates this entry's bytes. Guarded by the store's mutex: a spill rewrites it while readers
	// may be asking for it.
	ref blobRef
}

// blobRef is either bytes held in memory or a region of the store's overflow file; mem is nil once
// the entry has been written out.
type blobRef struct {
	mem    []byte
	offset int64
	length int64
}

// EntryStore holds one extracted archive's entries in memory while the memory limit admits them, and
// in a single overflow blob once it does not; an archive that fits in memory never touches disk. The
// store owns the overflow file and closes it on Close; readers from Open are valid only until then.
type EntryStore struct {
	mu sync.RWMutex

	entries []*Entry

	workDir *WorkDir
	file    *os.File
	written int64

	// archive names this store's archive in the events it sends, attributing a spill to its cause.
	archive string
	notify  Notify
}

// overflowBlobName is the file entries spill into. It has no framing: entry offsets live in the store.
const overflowBlobName = "contents.blob"

// indexRecordOverhead is the fixed memory kept per entry regardless of content: the *Entry (tar.Header
// plus blobRef), its slot in the entries slice, and append's headroom.
//
// It covers only what the store keeps. The resolver built over these entries keeps several times as
// much in nodes the store cannot count, and charges for that itself; see Charge.IndexRecord.
var indexRecordOverhead = int64(reflect.TypeFor[Entry]().Size()) + 24

// indexRecordCost is what one entry's record charges: the fixed overhead plus the two header strings.
func indexRecordCost(hdr tar.Header) int64 {
	return indexRecordOverhead + int64(len(hdr.Name)) + int64(len(hdr.Linkname))
}

var _ EntrySink = (*EntryStore)(nil)

// NewEntryStore returns a store that spills into workDir, naming archive in its events. The directory
// is created only on spill, so an in-memory store creates nothing.
//
// The store has no memory budget of its own: it asks the limiter entry by entry and spills everything
// it holds on the first refusal.
func NewEntryStore(workDir *WorkDir, archive string, notify Notify) *EntryStore {
	return &EntryStore{workDir: workDir, archive: archive, notify: notify}
}

// Add stores one entry's header and content. Content is read now, not referenced: the archive's
// reader is sequential.
//
// It reads and charges copyChunkSize at a time rather than into a header-sized buffer (whose size is
// the archive's own claim), so an entry larger than the memory limit is not held in full before the
// limiter is asked. The first refusal spills this entry and everything else the store holds.
func (s *EntryStore) Add(hdr tar.Header, contents io.Reader, charge *Charge) (*Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// charge the record before holding the entry, so an archive of many near-empty entries is bounded
	// by the same budgets its content is. Refused only when neither budget admits it, truncating the
	// archive at the entries already stored.
	if !charge.IndexRecord(indexRecordCost(hdr)) {
		return nil, ErrDiskLimitReached
	}

	entry := &Entry{Header: hdr}
	s.entries = append(s.entries, entry)

	if hdr.Typeflag != tar.TypeReg || contents == nil {
		return entry, nil
	}

	var held bytes.Buffer
	chunk := make([]byte, copyChunkSize)
	for {
		n, readErr := contents.Read(chunk)
		if n > 0 {
			if !charge.Memory(int64(n)) {
				// memory full: held bytes join the spill, the rest streams straight into the blob
				entry.ref = memRef(&held)
				rest := io.MultiReader(bytes.NewReader(chunk[:n]), contents)
				return entry, s.spillThroughLocked(entry, rest, charge)
			}
			held.Write(chunk[:n])
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return nil, fmt.Errorf("unable to read archive entry %q: %w", hdr.Name, readErr)
		}
	}

	entry.ref = memRef(&held)
	return entry, nil
}

// memRef references bytes held in memory. The slice stays non-nil even when empty, since a nil
// blobRef.mem means the bytes are on disk - which a zero-length entry's are not.
func memRef(held *bytes.Buffer) blobRef {
	body := held.Bytes()
	if body == nil {
		body = []byte{}
	}
	return blobRef{mem: body, length: int64(len(body))}
}

// spillThroughLocked spills everything the store holds to the overflow blob and writes the rest of
// entry's content in behind it, charging the disk limit as it lands.
//
// entry is the newest, so spillLocked writes it last, ending its region right where the rest of its
// content goes. The two are contiguous, so the entry keeps one reference.
func (s *EntryStore) spillThroughLocked(entry *Entry, rest io.Reader, charge *Charge) error {
	spilled := entry.ref.length
	moved, movedBytes, err := s.spillLocked(charge)
	if err != nil {
		return err
	}

	written, limitReached, err := copyCharged(io.NewOffsetWriter(s.file, s.written), rest, charge)
	s.written += written
	entry.ref = blobRef{offset: s.written - written - spilled, length: spilled + written}

	// reported after the move so the event counts streamed bytes as well as held ones
	if s.notify != nil && moved > 0 {
		s.notify(EntriesOverflowed{
			Archive: s.archive,
			Entries: moved,
			Bytes:   movedBytes + written,
			Reason:  overflowReason(charge),
		})
	}

	if err != nil {
		return fmt.Errorf("unable to write archive entry %q to the overflow blob: %w", entry.Header.Name, err)
	}
	if limitReached {
		return ErrDiskLimitReached
	}
	return nil
}

// spillLocked writes every memory-backed entry into the overflow blob and repoints it there,
// reporting what it moved. Any index over these entries is untouched: only blobRef changes. It sends
// no event; spillThroughLocked sends one once the triggering entry has also landed.
func (s *EntryStore) spillLocked(charge *Charge) (moved int, movedBytes int64, err error) {
	if s.file == nil {
		// first spill creates the work directory
		dir, err := s.workDir.Path()
		if err != nil {
			return 0, 0, err
		}
		f, err := os.OpenFile(filepath.Join(dir, overflowBlobName), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return 0, 0, fmt.Errorf("unable to create overflow blob: %w", err)
		}
		s.file = f
	}

	for _, entry := range s.entries {
		if entry.ref.mem == nil {
			continue
		}
		body := entry.ref.mem
		if !charge.Disk(int64(len(body))) {
			return moved, movedBytes, ErrDiskLimitReached
		}
		if _, err := s.file.WriteAt(body, s.written); err != nil {
			return moved, movedBytes, fmt.Errorf("unable to write archive entry %q to the overflow blob: %w", entry.Header.Name, err)
		}
		entry.ref = blobRef{offset: s.written, length: int64(len(body))}
		s.written += int64(len(body))
		moved++
		movedBytes += int64(len(body))
		// on disk now, so refund the memory it was charged
		charge.RefundMemory(int64(len(body)))
	}
	return moved, movedBytes, nil
}

// overflowReason distinguishes an archive spilled under memory pressure from one never held because
// the memory limit is zero.
func overflowReason(charge *Charge) OverflowReason {
	if charge != nil && charge.limiter != nil && charge.limiter.limits.MaxMemoryBytes == 0 {
		return MemoryHoldsNothing
	}
	return MemoryLimitReached
}

// Entries returns the entries stored so far, in the order they were added.
func (s *EntryStore) Entries() []*Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Entry, len(s.entries))
	copy(out, s.entries)
	return out
}

// Open returns a reader over one entry's content, from memory or the overflow blob. It supports Read,
// Seek and ReadAt either way, so a nested archive is extracted in place rather than copied out.
func (s *EntryStore) Open(entry *Entry) (ReaderAtSeeker, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if entry.ref.mem != nil {
		return bytes.NewReader(entry.ref.mem), nil
	}
	if entry.ref.length == 0 {
		return bytes.NewReader(nil), nil
	}
	if s.file == nil {
		return nil, fmt.Errorf("archive entry %q has no content", entry.Header.Name)
	}
	return io.NewSectionReader(s.file, entry.ref.offset, entry.ref.length), nil
}

// Close releases the overflow blob. Readers handed out by Open do not outlive it.
func (s *EntryStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil {
		return nil
	}
	err := s.file.Close()
	s.file = nil
	return err
}

// AddEntry stores one archive entry. There is no framing, so the disk limit is charged only when
// content reaches disk - never, for an archive that fits in memory.
func (s *EntryStore) AddEntry(f archives.FileInfo, result *ExtractionResult, charge *Charge) error {
	hdr, ok := entryHeader(f)
	if !ok {
		return nil
	}

	var contents io.ReadCloser
	if f.Mode().IsRegular() {
		opened, err := f.Open()
		if err != nil {
			log.WithFields("entry", f.NameInArchive, "error", err).
				Trace("unable to open archive entry, skipping it")
			return nil
		}
		contents = opened
	}

	_, err := s.Add(*hdr, contents, charge)
	if contents != nil {
		if closeErr := contents.Close(); closeErr != nil {
			log.WithFields("entry", f.NameInArchive, "error", closeErr).Trace("unable to close archive entry")
		}
	}

	switch {
	case errors.Is(err, ErrDiskLimitReached):
		// keep the entries stored so far rather than discard the archive
		result.Truncation = TruncatedByDiskLimit
		return errTruncated
	case err != nil:
		return err
	}

	return nil
}

// Finish is a no-op: entries are complete as added, with no framing to close off.
func (s *EntryStore) Finish(*ExtractionResult) {}

// OnDisk reports the entry content written out so far, which is what the disk limit was charged.
func (s *EntryStore) OnDisk() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.written
}
