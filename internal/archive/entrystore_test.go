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

func TestEntryStore_holdsSmallContentInMemory(t *testing.T) {
	dir := t.TempDir()
	s := NewEntryStore("app.zip", WorkDirAt(dir), memCharge(1024))
	t.Cleanup(func() { require.NoError(t, s.Close()) })

	require.NoError(t, s.Add(regularHeader("a.txt", 5), bytes.NewReader([]byte("hello"))))

	assert.Equal(t, int64(5), s.heldInMemory())
	assert.NoFileExists(t, filepath.Join(dir, entriesFileName))
	assert.Equal(t, "hello", readEntry(t, s.Open(s.Entries()[0])))
}

func TestEntryStore_overflowsToDiskAndKeepsTheSameEntries(t *testing.T) {
	// an index over these entries is not rebuilt when content moves
	dir := t.TempDir()
	s := NewEntryStore("app.zip", WorkDirAt(dir), memCharge(8))
	t.Cleanup(func() { require.NoError(t, s.Close()) })

	require.NoError(t, s.Add(regularHeader("a.txt", 4), bytes.NewReader([]byte("aaaa"))))
	first := s.Entries()[0]
	require.Equal(t, int64(4), s.heldInMemory())

	require.NoError(t, s.Add(regularHeader("b.txt", 6), bytes.NewReader([]byte("bbbbbb"))))

	assert.Zero(t, s.heldInMemory(), "everything moves out, not just the entry that did not fit")
	assert.FileExists(t, filepath.Join(dir, entriesFileName))
	assert.Equal(t, int64(10), s.OnDisk())

	entries := s.Entries()
	require.Len(t, entries, 2)
	assert.Same(t, first, entries[0], "entry identity survives the move")
	assert.Equal(t, "aaaa", readEntry(t, s.Open(entries[0])))
	assert.Equal(t, "bbbbbb", readEntry(t, s.Open(entries[1])))
}

func TestEntryStore_zeroMemoryHoldsNothing(t *testing.T) {
	dir := t.TempDir()
	s := NewEntryStore("app.zip", WorkDirAt(dir), memCharge(0))
	t.Cleanup(func() { require.NoError(t, s.Close()) })

	require.NoError(t, s.Add(regularHeader("a.txt", 3), bytes.NewReader([]byte("abc"))))

	assert.Zero(t, s.heldInMemory())
	assert.FileExists(t, filepath.Join(dir, entriesFileName))
	assert.Equal(t, "abc", readEntry(t, s.Open(s.Entries()[0])))
}

func TestEntryStore_negativeMemoryNeverOverflows(t *testing.T) {
	dir := t.TempDir()
	s := NewEntryStore("app.zip", WorkDirAt(dir), memCharge(-1))
	t.Cleanup(func() { require.NoError(t, s.Close()) })

	for _, body := range []string{"one", "two", "three"} {
		require.NoError(t, s.Add(regularHeader(body+".txt", int64(len(body))), bytes.NewReader([]byte(body))))
	}

	assert.Equal(t, int64(11), s.heldInMemory())
	assert.NoFileExists(t, filepath.Join(dir, entriesFileName))
}

func TestEntryStore_refusedEntryIsNotStored(t *testing.T) {
	// a half-stored pom a cataloger parses is worse than an absent one
	s := storeFor(t, NewLimiter(Limits{MaxMemoryBytes: 0, MaxDiskBytes: 0}).Charge())

	err := s.Add(regularHeader("a.txt", 3), bytes.NewReader([]byte("abc")))
	assert.ErrorIs(t, err, ErrDiskLimitReached)
	assert.Empty(t, s.Entries())
}

func TestEntryStore_directoryEntriesHoldNoContent(t *testing.T) {
	s := storeFor(t, memCharge(1024))

	require.NoError(t, s.Add(tar.Header{Name: "lib", Typeflag: tar.TypeDir, Mode: 0o755}, nil))

	assert.Zero(t, s.heldInMemory())
	assert.Empty(t, readEntry(t, s.Open(s.Entries()[0])))
}

func TestEntryStore_indexCostIsChargedEvenForEmptyContent(t *testing.T) {
	// the index estimate is what bounds an archive of many empty entries
	limiter := NewLimiter(Limits{MaxMemoryBytes: 1 << 20, MaxDiskBytes: -1})
	s := storeFor(t, limiter.Charge())

	hdr := regularHeader("a.txt", 0)
	require.NoError(t, s.Add(hdr, bytes.NewReader(nil)))

	mem, _ := limiter.InUse()
	assert.Equal(t, approxIndexBytes(hdr), mem)
	assert.Zero(t, s.heldInMemory())
}

func TestEntryStore_indexCostFallsBackToDiskWhenMemoryIsZero(t *testing.T) {
	limiter := NewLimiter(Limits{MaxMemoryBytes: 0, MaxDiskBytes: -1})
	s := storeFor(t, limiter.Charge())

	hdr := regularHeader("a.txt", 0)
	require.NoError(t, s.Add(hdr, bytes.NewReader(nil)))

	mem, disk := limiter.InUse()
	assert.Zero(t, mem)
	assert.Equal(t, approxIndexBytes(hdr), disk)
}

func TestEntryStore_refusesEntriesWhenNoBudgetAdmitsTheIndex(t *testing.T) {
	room := approxIndexBytes(regularHeader("x", 0)) * 3
	s := storeFor(t, NewLimiter(Limits{MaxMemoryBytes: 0, MaxDiskBytes: room}).Charge())

	var err error
	admitted := 0
	for i := 0; i < 100 && err == nil; i++ {
		if err = s.Add(regularHeader("x", 0), bytes.NewReader(nil)); err == nil {
			admitted++
		}
	}
	require.ErrorIs(t, err, ErrDiskLimitReached)
	assert.Equal(t, 3, admitted)
}

func TestEntryStore_readsAfterCloseFail(t *testing.T) {
	s := storeFor(t, memCharge(0))
	require.NoError(t, s.Add(regularHeader("a.txt", 5), bytes.NewReader([]byte("hello"))))
	entry := s.Entries()[0]
	require.Equal(t, "hello", readEntry(t, s.Open(entry)))

	require.NoError(t, s.Close())

	_, err := io.ReadAll(s.Open(entry))
	assert.Error(t, err)
	assert.NoError(t, s.Close(), "Close is idempotent")
}
