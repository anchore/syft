package archive

import (
	"archive/tar"
	"bytes"
	"io"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func regularHeader(name string, size int64) tar.Header {
	return tar.Header{Name: name, Size: size, Mode: 0o600, Typeflag: tar.TypeReg}
}

func readEntry(t *testing.T, r ReaderAtSeeker) string {
	t.Helper()
	_, err := r.Seek(0, io.SeekStart)
	require.NoError(t, err)
	b, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(b)
}

func TestEntryStore_holdsSmallContentInMemory(t *testing.T) {
	dir := t.TempDir()
	s := NewEntryStore(dir, "app.zip", nil)
	charge := memCharge(1024)
	t.Cleanup(func() { require.NoError(t, s.Close()) })

	entry, err := s.Add(regularHeader("a.txt", 5), bytes.NewReader([]byte("hello")), charge)
	require.NoError(t, err)

	assert.Equal(t, int64(5), s.HeldInMemory())
	assert.NoFileExists(t, filepath.Join(dir, overflowBlobName),
		"a small archive must not touch the disk at all - that is the whole point of the store")

	r, err := s.Open(entry)
	require.NoError(t, err)
	assert.Equal(t, "hello", readEntry(t, r))
}

func TestEntryStore_spillsToDiskAndKeepsTheSameEntries(t *testing.T) {
	// the index over these entries is not rebuilt when content moves, so the entry pointers and their
	// contents must both survive the move
	dir := t.TempDir()
	s := NewEntryStore(dir, "app.zip", nil)
	charge := memCharge(8)
	t.Cleanup(func() { require.NoError(t, s.Close()) })

	first, err := s.Add(regularHeader("a.txt", 4), bytes.NewReader([]byte("aaaa")), charge)
	require.NoError(t, err)
	require.Equal(t, int64(4), s.HeldInMemory())

	// the second entry takes the store past its memory bound, so everything held moves out
	second, err := s.Add(regularHeader("b.txt", 6), bytes.NewReader([]byte("bbbbbb")), charge)
	require.NoError(t, err)

	assert.Zero(t, s.HeldInMemory(), "everything must have moved out, not just the entry that did not fit")
	assert.FileExists(t, filepath.Join(dir, overflowBlobName))

	// the same entry pointers still read their own content, from their new home
	firstReader, err := s.Open(first)
	require.NoError(t, err)
	assert.Equal(t, "aaaa", readEntry(t, firstReader))

	secondReader, err := s.Open(second)
	require.NoError(t, err)
	assert.Equal(t, "bbbbbb", readEntry(t, secondReader))

	assert.Equal(t, []*Entry{first, second}, s.Entries(), "order and identity must be unchanged by the move")
}

func TestEntryStore_zeroMemoryHoldsNothing(t *testing.T) {
	// the reading a zero memory limit has everywhere else: none of that resource may be used
	dir := t.TempDir()
	s := NewEntryStore(dir, "app.zip", nil)
	charge := memCharge(0)
	t.Cleanup(func() { require.NoError(t, s.Close()) })

	entry, err := s.Add(regularHeader("a.txt", 3), bytes.NewReader([]byte("abc")), charge)
	require.NoError(t, err)

	assert.Zero(t, s.HeldInMemory())
	assert.FileExists(t, filepath.Join(dir, overflowBlobName))

	r, err := s.Open(entry)
	require.NoError(t, err)
	assert.Equal(t, "abc", readEntry(t, r))
}

func TestEntryStore_negativeMemoryNeverSpills(t *testing.T) {
	dir := t.TempDir()
	s := NewEntryStore(dir, "app.zip", nil)
	charge := memCharge(-1)
	t.Cleanup(func() { require.NoError(t, s.Close()) })

	for _, body := range []string{"one", "two", "three"} {
		_, err := s.Add(regularHeader(body+".txt", int64(len(body))), bytes.NewReader([]byte(body)), charge)
		require.NoError(t, err)
	}

	assert.Equal(t, int64(11), s.HeldInMemory())
	assert.NoFileExists(t, filepath.Join(dir, overflowBlobName))
}

func TestEntryStore_spillIsRefusedWhenDiskIsNotAvailable(t *testing.T) {
	// content that does not fit in memory and cannot be written has nowhere to go, and the archive is
	// skipped rather than cataloged as if it were empty
	dir := t.TempDir()
	s := NewEntryStore(dir, "app.zip", nil)
	t.Cleanup(func() { require.NoError(t, s.Close()) })

	nowhereToPutIt := NewLimiter(Limits{MaxMemoryBytes: 0, MaxDiskBytes: 0}).Charge()
	_, err := s.Add(regularHeader("a.txt", 3), bytes.NewReader([]byte("abc")), nowhereToPutIt)
	assert.ErrorIs(t, err, ErrDiskLimitReached)
}

func TestEntryStore_directoryEntriesHoldNoContent(t *testing.T) {
	dir := t.TempDir()
	s := NewEntryStore(dir, "app.zip", nil)
	charge := memCharge(1024)
	t.Cleanup(func() { require.NoError(t, s.Close()) })

	entry, err := s.Add(tar.Header{Name: "lib/", Typeflag: tar.TypeDir, Mode: 0o755}, nil, charge)
	require.NoError(t, err)

	assert.Zero(t, s.HeldInMemory())
	r, err := s.Open(entry)
	require.NoError(t, err)
	assert.Empty(t, readEntry(t, r))
}

// memCharge is a charge against a memory bound with disk left unbounded, which is the shape the store
// reads: hold while memory admits, move out when it does not.
func memCharge(maxMemory int64) *Charge {
	return NewLimiter(Limits{MaxMemoryBytes: maxMemory, MaxDiskBytes: -1}).Charge()
}

func TestEntryStore_chargesIndexRecordEvenForEmptyContent(t *testing.T) {
	// an empty entry still charges its index record - the header and node held to reach it - which is
	// what bounds entry count, the dimension the content-byte budgets never bounded.
	dir := t.TempDir()
	s := NewEntryStore(dir, "app.zip", nil)
	limiter := NewLimiter(Limits{MaxMemoryBytes: 1 << 20, MaxDiskBytes: -1})
	charge := limiter.Charge()
	t.Cleanup(func() { require.NoError(t, s.Close()) })

	hdr := regularHeader("a.txt", 0)
	_, err := s.Add(hdr, bytes.NewReader(nil), charge)
	require.NoError(t, err)

	mem, _ := limiter.InUse()
	assert.Equal(t, indexRecordCost(hdr), mem, "the index record is charged to memory")
	assert.Equal(t, int64(0), s.HeldInMemory(), "no content was held")
}

func TestEntryStore_indexOverflowsToDiskWhenMemoryIsZero(t *testing.T) {
	// the index cannot be refused just because memory is zero: a resolver still needs the records to
	// reach content that lives entirely on disk. With disk unbounded, every entry is admitted and its
	// record charged to disk instead.
	dir := t.TempDir()
	s := NewEntryStore(dir, "app.zip", nil)
	limiter := NewLimiter(Limits{MaxMemoryBytes: 0, MaxDiskBytes: -1})
	charge := limiter.Charge()
	t.Cleanup(func() { require.NoError(t, s.Close()) })

	hdr := regularHeader("a.txt", 0)
	_, err := s.Add(hdr, bytes.NewReader(nil), charge)
	require.NoError(t, err)

	mem, disk := limiter.InUse()
	assert.Equal(t, int64(0), mem, "memory budget is zero, so nothing is charged there")
	assert.Equal(t, indexRecordCost(hdr), disk, "the index record overflows to the disk budget")
}

func TestEntryStore_refusesEntriesWhenNoBudgetAdmitsTheIndex(t *testing.T) {
	// with memory zero and only a few index records' worth of disk, the store admits a bounded number
	// of entries and then refuses - an archive of millions of empty entries can no longer grow the
	// index without limit.
	dir := t.TempDir()
	s := NewEntryStore(dir, "app.zip", nil)
	room := indexRecordCost(regularHeader("x", 0)) * 3
	charge := NewLimiter(Limits{MaxMemoryBytes: 0, MaxDiskBytes: room}).Charge()
	t.Cleanup(func() { require.NoError(t, s.Close()) })

	var err error
	admitted := 0
	for i := 0; i < 100; i++ {
		if _, err = s.Add(regularHeader("x", 0), bytes.NewReader(nil), charge); err != nil {
			break
		}
		admitted++
	}
	require.ErrorIs(t, err, ErrDiskLimitReached)
	assert.Equal(t, 3, admitted, "exactly the index records that fit the disk budget were admitted")
}
