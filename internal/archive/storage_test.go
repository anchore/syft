package archive

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/tmpdir"
	"github.com/anchore/syft/syft/file"
)

// unboundedLimits hold everything in memory, as an archive well inside the default bounds does.
var unboundedLimits = Limits{MaxMemoryBytes: -1, MaxDiskBytes: -1}

// spillingLimits hold nothing in memory, so every entry lands in the store's overflow blob. The
// filesystem-cost requirement must be measured in this shape: an archive that never touches disk
// satisfies it trivially.
var spillingLimits = Limits{MaxMemoryBytes: 0, MaxDiskBytes: -1}

func TestStorage_filesystemCostDoesNotTrackEntryCount(t *testing.T) {
	// an archive of a hundred thousand entries must not put a hundred thousand files on the filesystem.
	// Asserted as an exact set of paths for two archives three orders of magnitude apart in entry count,
	// since a count that merely grows slowly would pass a bound and still be proportional to content.
	_, smallStore, smallRoot := extractedStore(t, manyEntryZip(t, 2), spillingLimits)
	_, largeStore, largeRoot := extractedStore(t, manyEntryZip(t, 5000), spillingLimits)
	smallWork, largeWork := workDirIn(t, smallRoot), workDirIn(t, largeRoot)

	// the archive's own bytes spill too under a zero memory bound, so the set is the spilled archive and
	// the blob its entries went into - two, whatever it holds
	want := []string{"app.zip", "contents.blob"}
	assert.Equal(t, want, filesystemEntries(t, smallWork))
	assert.Equal(t, want, filesystemEntries(t, largeWork),
		"5000 entries must cost the same filesystem entries as 2")

	// and the entries really are all there, so this is not passing because nothing was extracted
	assert.Len(t, smallStore.Entries(), 2)
	assert.Len(t, largeStore.Entries(), 5000)

	// an archive costs its entry content and nothing else on disk: no headers, no padding, so a one-byte
	// entry costs one byte
	assert.Equal(t, int64(5000), largeStore.OnDisk())
	assert.Equal(t, int64(2), smallStore.OnDisk())
}

func TestStorage_anArchiveWithinTheMemoryBoundTouchesNoFilesystemAtAll(t *testing.T) {
	// an archive that fits in memory pays for no write at all - not even the directory it would have
	// written into, which is created only when something actually spills
	_, store, root := extractedStore(t, manyEntryZip(t, 5000), unboundedLimits)

	assert.Len(t, store.Entries(), 5000)
	assert.Zero(t, store.OnDisk())
	assert.Empty(t, filesystemEntries(t, root),
		"an archive held entirely in memory creates no work directory at all")
}

func TestStorage_cleanupRemovesOneFileAndDoesNotWalkPerEntry(t *testing.T) {
	// cleanup is bounded by the same constant as the extraction, so the count of things removed is
	// asserted rather than only that the directory is gone
	extracted, _, root := extractedStore(t, manyEntryZip(t, 5000), spillingLimits)
	workDir := workDirIn(t, root)

	before := filesystemEntries(t, workDir)
	require.Len(t, before, 2, "the release has two things to remove whatever the archive held")

	extracted.Cleanup()

	_, err := os.Stat(filepath.Join(workDir, overflowBlobName))
	assert.True(t, os.IsNotExist(err), "the one file holding every entry must be gone")
	_, err = os.Stat(workDir)
	assert.True(t, os.IsNotExist(err), "and so must the work directory")

	// safe to call more than once, since the cataloger defers it past the sub-pipeline and recursion
	extracted.Cleanup()
}

func TestStorage_anEntryAtTheEndIsReadBySeeking(t *testing.T) {
	// "overflow content MUST remain directly readable without re-reading or re-decompressing what
	// precedes it". Asserted through the mechanism: the store records where the last entry's content
	// begins, near the end of a blob whose earlier entries are large, and hands back a bounded window
	// onto the file at that offset.
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

	_, store, root := extractedStore(t, &buf, spillingLimits)

	blobPath := filepath.Join(workDirIn(t, root), overflowBlobName)
	info, err := os.Stat(blobPath)
	require.NoError(t, err)
	total := info.Size()
	require.Greater(t, total, int64(8*filler), "the fixture must put real bulk ahead of the last entry")

	// the last entry's content sits near the end of the blob, so everything before it is what a
	// re-streaming design would have had to read
	body, err := os.ReadFile(blobPath)
	require.NoError(t, err)
	offset := int64(bytes.Index(body, []byte(wanted)))
	require.Positive(t, offset)
	assert.Greater(t, offset, total*9/10, "the last entry must really be at the end of the blob")

	entries := store.Entries()
	entry := entries[len(entries)-1]
	require.Equal(t, "zz-last.txt", entry.Header.Name)

	// the reader is bounded to this entry rather than the whole blob: its end is the entry's own size
	random, err := store.Open(entry)
	require.NoError(t, err)

	end, err := random.Seek(0, io.SeekEnd)
	require.NoError(t, err)
	assert.Equal(t, int64(len(wanted)), end)

	// offset zero of the reader is the last entry's first byte, not the blob's; a reader over the whole
	// file would answer with the first filler entry's content
	head := make([]byte, 8)
	_, err = random.ReadAt(head, 0)
	require.NoError(t, err)
	assert.Equal(t, wanted[:8], string(head))
}

func manyEntryZip(t *testing.T, count int) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i := range count {
		w, err := zw.Create(fmt.Sprintf("e%06d.txt", i))
		require.NoError(t, err)
		_, err = w.Write([]byte("x"))
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	return &buf
}

// extractedStore extracts one archive and returns the store its entries went into, with the scan temp
// root the extraction was pointed at.
//
// The root is where a work directory would appear: nothing the resolver is handed names a path on the
// host, and an archive that never writes creates no directory to name.
func extractedStore(t *testing.T, content io.Reader, limits Limits) (*ExtractedArchive, *EntryStore, string) {
	t.Helper()

	root := t.TempDir()
	ctx := tmpdir.WithValue(context.Background(), tmpdir.FromPath(root))

	var got *EntryStore
	factory := func(store *EntryStore, _ Overflow) (file.Resolver, IndexResult, error) {
		got = store
		return nil, IndexResult{}, nil
	}

	extracted, err := ExtractToResolver(
		ctx, content, "app.zip", "", "app.zip",
		DefaultExtractors(), NewLimiter(limits), factory, nil,
	)
	require.NoError(t, err)
	require.NotNil(t, extracted)
	t.Cleanup(extracted.Cleanup)

	return extracted, got, root
}

// workDirIn returns the one work directory an archive that spilled created under the scan temp root.
func workDirIn(t *testing.T, root string) string {
	t.Helper()
	children, err := os.ReadDir(root)
	require.NoError(t, err)
	require.Len(t, children, 1, "expected exactly one archive work directory under the temp root")
	return filepath.Join(root, children[0].Name())
}

// filesystemEntries is every directory entry under dir: an archive must not put one of these on the
// filesystem per entry it holds.
func filesystemEntries(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	require.NoError(t, filepath.WalkDir(dir, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(dir, p)
		if relErr != nil {
			return relErr
		}
		if rel == "." {
			return nil
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	}))
	return out
}
