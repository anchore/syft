package archive

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/tmpdir"
	"github.com/anchore/syft/syft/file"
)

func TestExtractToResolver_writesUnderTheScansTempRoot(t *testing.T) {
	// where an archive's scratch space lands is the scan's decision: the root on the context is what the
	// caller configured, and what gets cleaned up if an archive's own cleanup is missed
	root := t.TempDir()
	ctx := tmpdir.WithValue(context.Background(), tmpdir.FromPath(root))

	factory := func(_ *EntryStore, _ Overflow) (file.Resolver, IndexResult, error) {
		return nil, IndexResult{}, nil
	}

	// a zero memory bound, so this archive really does write: a work directory exists only once
	// something has spilled into it
	extracted, err := ExtractToResolver(
		ctx, newTestZip(t, map[string]string{"hello.txt": "hi"}), "app.zip", "", "app.zip",
		DefaultExtractors(), NewLimiter(Limits{MaxMemoryBytes: 0, MaxDiskBytes: -1}), factory, nil,
	)
	require.NoError(t, err)
	require.NotNil(t, extracted)
	t.Cleanup(extracted.Cleanup)

	// the work directory is not named by anything the resolver is handed, so it is observed where it
	// lands: under the temp root the scan configured
	workDirs := workDirsUnder(t, root)
	require.Len(t, workDirs, 1, "expected one archive work directory under the scan's temp root")

	// and the archive still cleans up after itself, so the root is a safety net rather than the only
	// thing reclaiming the space
	extracted.Cleanup()
	_, statErr := os.Stat(workDirs[0])
	assert.True(t, os.IsNotExist(statErr), "expected the archive work directory to be removed by Cleanup")
}

func TestExtractToResolver_anArchiveThatNeverWritesCreatesNoWorkDir(t *testing.T) {
	// the scratch directory is created at the point of writing, so an archive held entirely in memory -
	// which is most of them - costs no directory on the filesystem at all
	root := t.TempDir()
	ctx := tmpdir.WithValue(context.Background(), tmpdir.FromPath(root))

	factory := func(_ *EntryStore, _ Overflow) (file.Resolver, IndexResult, error) {
		return nil, IndexResult{}, nil
	}

	extracted, err := ExtractToResolver(
		ctx, newTestZip(t, map[string]string{"hello.txt": "hi"}), "app.zip", "", "app.zip",
		DefaultExtractors(), NewLimiter(Limits{MaxMemoryBytes: -1, MaxDiskBytes: -1}), factory, nil,
	)
	require.NoError(t, err)
	require.NotNil(t, extracted)
	t.Cleanup(extracted.Cleanup)

	assert.Empty(t, workDirsUnder(t, root), "nothing was written, so no work directory was created")

	// and cleanup of an archive that created nothing is still safe
	extracted.Cleanup()
	assert.Empty(t, workDirsUnder(t, root))
}

func TestExtractToResolver(t *testing.T) {
	content := newTestZip(t, map[string]string{"dir/hello.txt": "hello world"})

	var got Overflow
	var gotStore *EntryStore
	factory := func(store *EntryStore, overflow Overflow) (file.Resolver, IndexResult, error) {
		got, gotStore = overflow, store
		return nil, IndexResult{}, nil
	}

	extracted, err := ExtractToResolver(
		context.Background(), content, "some/path/app.zip", "parentFS", "app.war:some/path/app.zip",
		DefaultExtractors(), nil, factory, nil,
	)
	require.NoError(t, err)
	require.NotNil(t, extracted)
	t.Cleanup(extracted.Cleanup)

	// the filesystem the archive lives on is passed through unchanged; the nesting chain is carried
	// separately as the archive path, and both are handed to the resolver factory
	assert.Equal(t, "parentFS", extracted.FileSystemID)
	assert.Equal(t, "parentFS", got.FileSystemID)
	assert.Equal(t, "app.war:some/path/app.zip", got.ArchivePath)

	// the archive's entries are in the store handed to the factory, keyed by their archive-relative
	// path: nothing was unpacked to a directory for the resolver to be pointed at
	assert.Equal(t, "hello world", readStoreEntry(t, gotStore, "dir/hello.txt"))

	extracted.Cleanup()
}

func TestExtractToResolver_notAnArchive(t *testing.T) {
	factory := func(*EntryStore, Overflow) (file.Resolver, IndexResult, error) { return nil, IndexResult{}, nil }

	extracted, err := ExtractToResolver(
		context.Background(), strings.NewReader("this is not an archive"), "notes.txt", "", "notes.txt",
		DefaultExtractors(), nil, factory, nil,
	)
	require.NoError(t, err)
	assert.Nil(t, extracted, "non-archive content should yield a nil ExtractedArchive")
}

func TestExtractToResolver_passesTheArchivesChargeToTheIndex(t *testing.T) {
	// the index keeps more per entry than the store can measure - one node per path component - so it
	// charges the scan's limiter itself, against this archive's handle
	limiter := NewLimiter(Limits{MaxMemoryBytes: 1 << 20, MaxDiskBytes: 1 << 20})

	var got Overflow
	factory := func(_ *EntryStore, overflow Overflow) (file.Resolver, IndexResult, error) {
		got = overflow
		return nil, IndexResult{}, nil
	}

	extracted, err := ExtractToResolver(
		context.Background(), newTestZip(t, map[string]string{"hello.txt": "hi"}), "app.zip", "", "app.zip",
		DefaultExtractors(), limiter, factory, nil,
	)
	require.NoError(t, err)
	require.NotNil(t, extracted)
	t.Cleanup(extracted.Cleanup)

	require.NotNil(t, got.Charge, "the index must be handed this archive's charge, not left unbounded")

	// and it is this archive's handle, so Cleanup gives back whatever the index charged through it
	require.True(t, got.Charge.Memory(4096))
	before, _ := limiter.InUse()
	require.Positive(t, before)

	extracted.Cleanup()
	after, _ := limiter.InUse()
	assert.Zero(t, after, "everything the archive charged, the index included, is released with it")
}

func TestExtractToResolver_reportsAnIndexThatRanOutOfBudget(t *testing.T) {
	// an index that stops part way is a truncation, not a failure: the archive is cataloged from what was
	// indexed, and the reason names the index rather than the disk, which nothing was written to
	factory := func(_ *EntryStore, _ Overflow) (file.Resolver, IndexResult, error) {
		return nil, IndexResult{Truncated: true}, nil
	}

	extracted, err := ExtractToResolver(
		context.Background(), newTestZip(t, map[string]string{"a.txt": "a", "b.txt": "b"}), "app.zip", "", "app.zip",
		DefaultExtractors(), nil, factory, nil,
	)
	require.NoError(t, err)
	require.NotNil(t, extracted)
	t.Cleanup(extracted.Cleanup)

	assert.True(t, extracted.Result.Truncated())
	assert.Equal(t, TruncatedByIndexLimit, extracted.Result.Truncation)
}

// workDirsUnder returns the archive work directories directly under the scan's temp root.
func workDirsUnder(t *testing.T, root string) []string {
	t.Helper()
	children, err := os.ReadDir(root)
	require.NoError(t, err)

	var out []string
	for _, child := range children {
		if child.IsDir() && strings.HasPrefix(child.Name(), workDirName) {
			out = append(out, filepath.Join(root, child.Name()))
		}
	}
	return out
}

func readStoreEntry(t *testing.T, store *EntryStore, name string) string {
	t.Helper()
	require.NotNil(t, store)
	for _, entry := range store.Entries() {
		if entry.Header.Name != name {
			continue
		}
		reader, err := store.Open(entry)
		require.NoError(t, err)
		body, err := io.ReadAll(reader)
		require.NoError(t, err)
		return string(body)
	}
	t.Fatalf("no entry %q in the store", name)
	return ""
}

func newTestZip(t *testing.T, files map[string]string) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		require.NoError(t, err)
		_, err = w.Write([]byte(body))
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	return &buf
}
