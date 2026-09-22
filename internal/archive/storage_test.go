package archive

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	unboundedLimits = Limits{MaxMemoryBytes: -1, MaxDiskBytes: -1}

	// spillingLimits hold nothing in memory, so every entry lands in the overflow file
	spillingLimits = Limits{MaxMemoryBytes: 0, MaxDiskBytes: -1}
)

func TestStorage_filesystemCostDoesNotTrackEntryCount(t *testing.T) {
	_, smallStore, smallRoot := extractedStore(t, manyEntryZip(t, 2), spillingLimits)
	_, largeStore, largeRoot := extractedStore(t, manyEntryZip(t, 5000), spillingLimits)

	want := []string{entriesFileName}
	assert.Equal(t, want, filesystemEntries(t, workDirIn(t, smallRoot)))
	assert.Equal(t, want, filesystemEntries(t, workDirIn(t, largeRoot)), "5000 entries cost the same filesystem entries as 2")

	assert.Len(t, smallStore.Entries(), 2)
	assert.Len(t, largeStore.Entries(), 5000)

	// entries cost their content and nothing else on disk: no headers, no padding
	assert.Equal(t, int64(2), smallStore.OnDisk())
	assert.Equal(t, int64(5000), largeStore.OnDisk())
}

func TestStorage_anArchiveWithinTheMemoryBoundTouchesNoFilesystemAtAll(t *testing.T) {
	_, store, root := extractedStore(t, manyEntryZip(t, 5000), unboundedLimits)

	assert.Len(t, store.Entries(), 5000)
	assert.Zero(t, store.OnDisk())
	assert.Empty(t, filesystemEntries(t, root))
}

func TestStorage_cleanupRemovesTheWorkDirectory(t *testing.T) {
	extracted, _, root := extractedStore(t, manyEntryZip(t, 5000), spillingLimits)
	workDir := workDirIn(t, root)
	require.Len(t, filesystemEntries(t, workDir), 1)

	extracted.Cleanup()

	assert.NoDirExists(t, workDir)
	extracted.Cleanup()
}

func TestStorage_anEntryAtTheEndIsReadBySeeking(t *testing.T) {
	// the reader over an entry is a bounded window at its offset, not a re-read of what precedes it
	const filler = 64 * 1024

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i := range 8 {
		w, err := zw.Create(fmt.Sprintf("filler%d.bin", i))
		require.NoError(t, err)
		_, err = w.Write(bytes.Repeat([]byte{byte(i)}, filler))
		require.NoError(t, err)
	}
	last, err := zw.Create("zz-last.txt")
	require.NoError(t, err)
	wanted := strings.Repeat("last", 64)
	_, err = last.Write([]byte(wanted))
	require.NoError(t, err)
	require.NoError(t, zw.Close())

	_, store, root := extractedStore(t, buf.Bytes(), spillingLimits)

	body, err := os.ReadFile(filepath.Join(workDirIn(t, root), entriesFileName))
	require.NoError(t, err)
	offset := int64(bytes.Index(body, []byte(wanted)))
	require.Greater(t, offset, int64(len(body))*9/10, "the last entry must really be at the end of the file")

	entries := store.Entries()
	entry := entries[len(entries)-1]
	require.Equal(t, "zz-last.txt", entry.Header.Name)

	reader := store.Open(entry)
	end, err := reader.Seek(0, io.SeekEnd)
	require.NoError(t, err)
	assert.Equal(t, int64(len(wanted)), end)

	head := make([]byte, 8)
	_, err = reader.ReadAt(head, 0)
	require.NoError(t, err)
	assert.Equal(t, wanted[:8], string(head))
}

func manyEntryZip(t *testing.T, count int) []byte {
	t.Helper()
	files := make(map[string]string, count)
	for i := range count {
		files[fmt.Sprintf("e%06d.txt", i)] = "x"
	}
	return zipBytes(t, files)
}

// extractedStore extracts one archive and returns the store its entries went into, along with the
// scan temp root its work directory would appear under.
func extractedStore(t *testing.T, data []byte, limits Limits) (*Extracted, *EntryStore, string) {
	t.Helper()
	ctx, root := scanContext(t)

	extracted, err := Extract(ctx, bytes.NewReader(data), "", "app.zip", NewLimiter(limits), nil)
	require.NoError(t, err)
	require.NotNil(t, extracted)
	t.Cleanup(extracted.Cleanup)

	return extracted, extracted.Resolver.(*Index).store, root
}

func workDirIn(t *testing.T, root string) string {
	t.Helper()
	dirs := workDirsUnder(t, root)
	require.Len(t, dirs, 1)
	return dirs[0]
}

// filesystemEntries is every directory entry under dir, recursively.
func filesystemEntries(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	require.NoError(t, filepath.WalkDir(dir, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if rel, _ := filepath.Rel(dir, p); rel != "." {
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	}))
	return out
}
