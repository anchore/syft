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

	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/file"
)

// manyEntryZip builds a zip of count small entries, in sorted name order.
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

// extractedOverflow extracts one archive and hands back where its content went, along with the work
// directory holding it - which is what a filesystem cost has to be measured against.
func extractedOverflow(t *testing.T, content io.Reader, limits ExtractionLimits) (*ExtractedArchive, Overflow, string) {
	t.Helper()

	var got Overflow
	factory := func(overflow Overflow) (file.Resolver, IndexResult, error) {
		got = overflow
		return nil, IndexResult{}, nil
	}

	extracted, err := ExtractToResolver(
		context.Background(), content, "app.zip", "", "app.zip",
		DefaultExtractors(), NewLimiter(Limits{MaxMemoryBytes: -1, MaxDiskBytes: -1}), limits, factory, nil, nil,
	)
	require.NoError(t, err)
	require.NotNil(t, extracted)
	t.Cleanup(extracted.Cleanup)

	return extracted, got, filepath.Dir(got.TarPath)
}

// filesystemEntries is every directory entry under dir, path by path, which is the cost the
// requirement is about: an archive must not put one of these on the filesystem per entry it holds.
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

func TestOverflow_filesystemCostDoesNotTrackEntryCount(t *testing.T) {
	// the requirement this whole shape exists for: an archive of a hundred thousand entries must not
	// put a hundred thousand files on the filesystem. Asserted as an exact set of paths for two
	// archives three orders of magnitude apart in entry count, rather than as a bound - a count that
	// merely grows slowly would pass a bound and still be proportional to content.
	small, smallOverflow, smallWork := extractedOverflow(t, manyEntryZip(t, 2), ExtractionLimits{})
	large, largeOverflow, largeWork := extractedOverflow(t, manyEntryZip(t, 5000), ExtractionLimits{})

	want := []string{"contents", "contents.tar"}
	assert.Equal(t, want, filesystemEntries(t, smallWork))
	assert.Equal(t, want, filesystemEntries(t, largeWork),
		"5000 entries must cost the same filesystem entries as 2: one tar, plus the empty root their "+
			"paths are reported relative to")

	// and the entries really are all there, so this is not passing because nothing was extracted
	assert.Equal(t, 2, countTarEntries(t, smallOverflow.TarPath))
	assert.Equal(t, 5000, countTarEntries(t, largeOverflow.TarPath))
	// what one archive costs on disk, exactly: a header block and a padded data block per entry, plus
	// the two-block end-of-archive marker. This is the figure the disk limit is charged, which is why
	// a limit expressed in entry bytes now under-counts.
	assert.Equal(t, int64((5000*2+2)*tarBlockSize), large.Result.BytesWritten)
	assert.Equal(t, int64((2*2+2)*tarBlockSize), small.Result.BytesWritten)
}

func TestOverflow_cleanupRemovesOneFileAndDoesNotWalkPerEntry(t *testing.T) {
	// cleanup was proportional to content too: releasing an archive meant removing one filesystem
	// entry per archive entry. It is now bounded by the same constant as the extraction, so the count
	// of things removed is asserted rather than just the fact that the directory is gone.
	extracted, overflow, workDir := extractedOverflow(t, manyEntryZip(t, 5000), ExtractionLimits{})

	before := filesystemEntries(t, workDir)
	require.Len(t, before, 2, "the release has two things to remove whatever the archive held")

	extracted.Cleanup()

	_, err := os.Stat(overflow.TarPath)
	assert.True(t, os.IsNotExist(err), "the one file holding every entry must be gone")
	_, err = os.Stat(workDir)
	assert.True(t, os.IsNotExist(err), "and so must the work directory")

	// safe to call more than once, since the cataloger defers it past the sub-pipeline and past
	// recursion
	extracted.Cleanup()
}

func TestOverflow_anEntryAtTheEndIsReadBySeeking(t *testing.T) {
	// "overflow content MUST remain directly readable without re-reading or re-decompressing what
	// precedes it". A design that met the entry-count requirement by re-streaming the whole archive
	// per read would not satisfy it, so what is asserted here is the mechanism: the index records
	// where the last entry's content begins, near the end of a tar whose earlier entries are large,
	// and the reader it hands back is a bounded window onto the file at that offset.
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

	_, overflow, _ := extractedOverflow(t, &buf, ExtractionLimits{})

	info, err := os.Stat(overflow.TarPath)
	require.NoError(t, err)
	total := info.Size()
	require.Greater(t, total, int64(8*filler), "the fixture must put real bulk ahead of the last entry")

	// the last entry's content sits near the end of the tar, which is the only reason a seek to it is
	// worth anything: everything before it is what a re-streaming design would have had to read
	offset := int64(bytes.Index(readFile(t, overflow.TarPath), []byte(wanted)))
	require.Positive(t, offset)
	assert.Greater(t, offset, total*9/10, "the last entry must really be at the end of the tar")

	entry := tarEntryNamed(t, overflow.TarPath, "zz-last.txt")

	contents := entry.Open()
	t.Cleanup(func() { require.NoError(t, contents.Close()) })

	random, ok := contents.(interface {
		io.ReaderAt
		io.Seeker
	})
	require.True(t, ok, "the entry reader must be random access, or a read cannot be a seek")

	// the reader is bounded to this entry rather than being a view of the whole tar: its end is the
	// entry's own size, so reading it cannot have read what precedes it
	end, err := random.Seek(0, io.SeekEnd)
	require.NoError(t, err)
	assert.Equal(t, int64(len(wanted)), end)

	// and offset zero of the reader is the last entry's first byte, not the tar's. A reader over the
	// whole file would answer this with the first filler entry's content.
	head := make([]byte, 8)
	_, err = random.ReadAt(head, 0)
	require.NoError(t, err)
	assert.Equal(t, wanted[:8], string(head))
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	body, err := os.ReadFile(path)
	require.NoError(t, err)
	return body
}

// countTarEntries is how many entries a tar on disk holds, read through the same index the resolver
// builds its filesystem from.
func countTarEntries(t *testing.T, tarPath string) int {
	t.Helper()
	count := 0
	_, err := stereoscopeFile.NewTarIndex(tarPath, func(stereoscopeFile.TarIndexEntry) error {
		count++
		return nil
	})
	require.NoError(t, err)
	return count
}

// tarEntryNamed is the index record for one entry of a tar, which is what carries its seek offset.
func tarEntryNamed(t *testing.T, tarPath, name string) stereoscopeFile.TarIndexEntry {
	t.Helper()
	var found *stereoscopeFile.TarIndexEntry
	_, err := stereoscopeFile.NewTarIndex(tarPath, func(entry stereoscopeFile.TarIndexEntry) error {
		if entry.ToTarFileEntry().Header.Name == name {
			e := entry
			found = &e
		}
		return nil
	})
	require.NoError(t, err)
	require.NotNil(t, found, "no entry %q in %q", name, tarPath)
	return *found
}
