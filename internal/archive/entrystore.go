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

// Entry is one archive entry held by an EntryStore: its header, and a reference to its bytes wherever
// they currently live.
//
// The bytes move; the entry does not. That is the point of this type - an index built over these
// entries stays valid when content is pushed out to disk, because what changes is the entry's
// reference and not its identity or its place in any index.
type Entry struct {
	Header tar.Header

	// ref names where this entry's bytes are right now. Guarded by the store's mutex, because a swap
	// to disk rewrites it while readers may be asking for it.
	ref blobRef
}

// blobRef is either bytes held in memory or a region of the store's overflow file. Exactly one of the
// two is live: mem is nil once the entry has been written out.
type blobRef struct {
	mem    []byte
	offset int64
	length int64
}

// EntryStore holds the entries of one extracted archive, in memory while the memory limit admits them
// and in a single overflow file once it does not.
//
// This replaces writing every archive's entries into a tar and indexing that tar by seek offset. A
// tar had to be on disk before there was anything to index, so a four-kilobyte jar paid for a file
// write and a tar walk before a cataloger could read a byte of it. Here the index is over the entries
// themselves, so a small archive never touches the disk at all, and a large one moves its bytes
// without the index noticing.
//
// The store owns the overflow file and closes it on Close. Readers handed out by Open borrow it, so
// they are only valid until then - which matches the lifetime the archive cataloger already gives an
// extracted archive.
type EntryStore struct {
	mu sync.RWMutex

	entries []*Entry

	// heldInMemory is the bytes currently held by entries whose ref is memory-backed. It falls to zero
	// when the store spills.
	heldInMemory int64

	workDir string
	file    *os.File
	written int64

	// archive names this store's archive in the events it sends, so a spill can be attributed to the
	// file that caused it rather than reported as an anonymous byte count.
	archive string
	notify  Notify
}

// overflowBlobName is the file an archive's entries are written into once they no longer fit in
// memory. Unlike the tar it replaces it has no framing: the entries' offsets live in the store, so
// nothing has to be parsed to find them again.
const overflowBlobName = "contents.blob"

// indexRecordOverhead approximates the fixed memory kept per entry no matter its content: the *Entry,
// its tar.Header, and the resolver node built over it. It is an over-estimate of the fixed part, with
// the variable part - the entry's name and link target - added on top, so the bound errs towards
// charging more rather than letting the index outrun what was accounted for. See Charge.IndexRecord.
var indexRecordOverhead = int64(reflect.TypeOf((*tar.Header)(nil)).Elem().Size())

// indexRecordCost is what one entry's index record charges: the fixed overhead plus the bytes of the
// two strings the header carries by value.
func indexRecordCost(hdr tar.Header) int64 {
	return indexRecordOverhead + int64(len(hdr.Name)) + int64(len(hdr.Linkname))
}

var _ EntrySink = (*EntryStore)(nil)

// NewEntryStore returns a store that writes its overflow blob into workDir, naming archive in the
// events it sends.
//
// How much it holds in memory is not a property of the store: it asks the scan's limiter, entry by
// entry, and moves what it is holding out to disk the first time the limiter says no. That keeps one
// answer to "how much memory is this scan using" rather than a per-archive budget that no one set.
func NewEntryStore(workDir, archive string, notify Notify) *EntryStore {
	return &EntryStore{workDir: workDir, archive: archive, notify: notify}
}

// Add stores one entry's header and content, and reports the entry.
//
// Content is read here rather than referenced: an archive's reader is sequential, so an entry that is
// not read now cannot be read later. Where it lands is decided as it arrives, which is what keeps the
// decision out of every read path downstream.
//
// It is read and charged copyChunkSize at a time rather than into a buffer sized by anything the
// entry declared, for the reason holdContent reads an archive's own bytes that way: a header's size
// is the archive's claim about itself, so an entry far larger than the memory limit would be held
// past it in full before the limiter was ever asked. Here the limiter is asked per chunk, and the
// first refusal moves this entry and everything the store is holding out to the overflow blob.
func (s *EntryStore) Add(hdr tar.Header, contents io.Reader, charge *Charge) (*Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// charge this entry's index record before it is held, so an archive of millions of near-empty
	// entries is bounded by the same budgets its content is rather than growing the index without
	// limit. The record overflows to disk when memory is full and is only refused when neither budget
	// admits it; a refusal leaves the archive truncated at the entries already stored.
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
				// memory is full: what is held of this entry joins the spill, and the rest of it
				// streams straight into the blob behind it rather than being read into memory first
				entry.ref = memRef(&held)
				s.heldInMemory += entry.ref.length
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
	s.heldInMemory += entry.ref.length
	return entry, nil
}

// memRef is a reference to bytes held in memory. The slice is taken non-nil even when it is empty,
// because nil is how blobRef says "these bytes are on disk" and a zero-length entry is not.
func memRef(held *bytes.Buffer) blobRef {
	body := held.Bytes()
	if body == nil {
		body = []byte{}
	}
	return blobRef{mem: body, length: int64(len(body))}
}

// spillThroughLocked moves everything the store is holding out to the overflow blob and writes the
// rest of entry's content in behind it, charging the disk limit as it lands.
//
// entry is the newest, so spillLocked writes it last and its region ends where the blob does - which
// is exactly where the rest of its content is about to go, so the two are one contiguous region and
// the entry keeps a single reference to it.
func (s *EntryStore) spillThroughLocked(entry *Entry, rest io.Reader, charge *Charge) error {
	spilled := entry.ref.length
	moved, movedBytes, err := s.spillLocked(charge)
	if err != nil {
		return err
	}

	written, limitReached, err := copyCharged(io.NewOffsetWriter(s.file, s.written), rest, charge)
	s.written += written
	entry.ref = blobRef{offset: s.written - written - spilled, length: spilled + written}

	// reported once the whole move is done, so the event counts the bytes that streamed through as
	// well as the ones that were being held: they all went to disk for the same reason.
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
// reporting what it moved. The index over these entries is untouched: an entry's identity is the
// pointer, and only its reference to its bytes changes.
//
// It does not send the event for the move: the entry that triggered the spill is still streaming in
// behind it, and an event sent from here would report a byte count short by whatever that entry has
// left. spillThroughLocked sends it once both halves have landed.
func (s *EntryStore) spillLocked(charge *Charge) (moved int, movedBytes int64, err error) {
	if s.file == nil {
		f, err := os.OpenFile(filepath.Join(s.workDir, overflowBlobName), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
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
		charged := charge != nil
		if _, err := s.file.WriteAt(body, s.written); err != nil {
			return moved, movedBytes, fmt.Errorf("unable to write archive entry %q to the overflow blob: %w", entry.Header.Name, err)
		}
		entry.ref = blobRef{offset: s.written, length: int64(len(body))}
		s.written += int64(len(body))
		moved++
		movedBytes += int64(len(body))
		if charged {
			// the bytes are on disk now, so the memory they were charged for is no longer held
			charge.RefundMemory(int64(len(body)))
		}
	}
	s.heldInMemory = 0
	return moved, movedBytes, nil
}

// overflowReason distinguishes an archive pushed to disk by pressure from one that was never going to
// be held at all, which are different findings: the first says the scan is at its memory bound, the
// second says the bound is zero.
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

// Open returns a reader over one entry's content, from memory or from the overflow blob as the entry
// currently stands. The reader is Read, Seek and ReadAt either way, so a nested archive is handed to
// an archive format where it lies rather than being copied out first.
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

// HeldInMemory reports the entry content currently held in memory, for tests and for the scan's own
// statistics.
func (s *EntryStore) HeldInMemory() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.heldInMemory
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

// AddEntry stores one archive entry, so an EntryStore can stand where an OverflowTar stands.
//
// Note what is NOT here: no header encoding, no block padding, and no end-of-archive marker, because
// there is no framing to write. The disk limit is charged only when content actually reaches the disk,
// which for a small archive is never - so an archive that fits in memory costs the limiter nothing on
// disk and costs the machine no write at all.
func (s *EntryStore) AddEntry(f archives.FileInfo, result *ExtractionResult, limits ExtractionLimits) error {
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

	entry, err := s.Add(*hdr, contents, limits.Charge)
	if contents != nil {
		if closeErr := contents.Close(); closeErr != nil {
			log.WithFields("entry", f.NameInArchive, "error", closeErr).Trace("unable to close archive entry")
		}
	}
	switch {
	case errors.Is(err, ErrDiskLimitReached):
		// nowhere left to put this archive's content: the entries stored so far stay, and the archive
		// is reported as truncated rather than discarded
		result.Truncation = TruncatedByDiskLimit
		return errTruncated
	case err != nil:
		return err
	}

	result.FilesExtracted++
	result.BytesWritten = s.OnDisk()
	_ = entry
	return nil
}

// Finish has nothing to write: a store's entries are complete as they are added, with no framing to
// close off.
func (s *EntryStore) Finish(*ExtractionResult, ExtractionLimits) {}

// OnDisk reports the entry content written out so far, which is what the disk limit was charged for.
func (s *EntryStore) OnDisk() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.written
}
