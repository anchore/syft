package fileresolver

import (
	"archive/tar"
	"context"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/archive"
	"github.com/anchore/syft/internal/tmpdir"
)

// Test_indexChargeCoversWhatTheIndexKeeps is what the cost constants in archive_index.go rest on.
//
// The charge exists to stop an archive before its index is built, so it must over-estimate what the
// index really retains. An under-count is worse than no limit at all: it reads as a configured bound
// while admitting some multiple of it. A previous accounting charged 216 bytes plus the name per
// entry where the index kept 627, and charged nothing for the directory nodes an entry's path
// implies - which a single entry can name 200,000 of.
func Test_indexChargeCoversWhatTheIndexKeeps(t *testing.T) {
	tests := []struct {
		name  string
		names []string
	}{
		{
			name: "flat, short names",
			names: func() []string {
				out := make([]string, 60000)
				for i := range out {
					out[i] = fmt.Sprintf("d/%06d", i)
				}
				return out
			}(),
		},
		{
			name: "nested, jar-shaped names",
			names: func() []string {
				out := make([]string, 60000)
				for i := range out {
					out[i] = fmt.Sprintf("com/example/pkg%03d/sub%02d/Thing%06d.class", i%500, i%50, i)
				}
				return out
			}(),
		},
		{
			name: "one entry per directory, so every entry synthesizes a chain",
			names: func() []string {
				out := make([]string, 20000)
				for i := range out {
					out[i] = fmt.Sprintf("a%05d/b%05d/c%05d/d%05d/file.txt", i, i, i, i)
				}
				return out
			}(),
		},
		{
			name:  "deep single entry, at the path cap",
			names: []string{strings.Repeat("a/", (maxEntryPathBytes-2)/2) + "f"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := storeOf(t, tt.names)
			limiter, charge := unboundedCharge()

			var index *ArchiveIndex
			kept := heapGrowth(t, func() {
				var err error
				index, err = NewFromArchiveEntries("", "outer.jar", store, charge)
				require.NoError(t, err)
			})
			require.False(t, index.Truncated(), "an unbounded charge must never truncate")

			charged, _ := limiter.InUse()
			t.Logf("entries=%d records=%d charged=%d kept=%d (charged/kept=%.2fx)",
				len(tt.names), index.Records(), charged, kept, float64(charged)/float64(kept))

			assert.GreaterOrEqual(t, charged, kept,
				"the index charged less than it kept, so the configured bound admits more than it says")

			// an over-estimate is the point, but one wildly over wastes the budget on archives doing
			// nothing wrong
			assert.Less(t, charged, kept*4,
				"the index charged several times what it kept, which spends a scan's budget on nothing")

			runtime.KeepAlive(index)
		})
	}
}

// Test_deepEntryPathsAreRefused covers the bound on an entry's path, which keeps one name from
// becoming an arbitrarily long chain of nodes.
func Test_deepEntryPathsAreRefused(t *testing.T) {
	atCap := strings.Repeat("a/", (maxEntryPathBytes-2)/2) + "f"
	overCap := strings.Repeat("a/", maxEntryPathBytes) + "f"

	require.LessOrEqual(t, len(atCap), maxEntryPathBytes)
	require.Greater(t, len(overCap), maxEntryPathBytes)

	index, err := NewFromArchiveEntries("", "outer.jar",
		storeOf(t, []string{"kept.txt", atCap, overCap}), nil)
	require.NoError(t, err)

	assert.Equal(t, 2, index.Records(), "the entry over the cap is dropped and the rest are kept")
	assert.True(t, index.HasPath("/kept.txt"))
	assert.True(t, index.HasPath("/"+atCap))
	assert.False(t, index.HasPath("/"+overCap))
	assert.False(t, index.Truncated(), "dropping an unusable name is not a budget truncation")
}

// Test_deepEntryPathsStayAffordable guards the two-pass placement in ArchiveIndex.node.
//
// Placing a node used to recurse from the leaf up, rebuilding the path with path.Dir at every level,
// making a chain cost work quadratic in its depth. Against the replacement: 400 entries sharing one
// deep prefix went from 9.8ms to 0.77ms, 400 entries each with their own chain from 2.87s to 0.33s,
// and a single 200,000-component name from 59.3s to 1.3s. That last shape no longer reaches here -
// sanitizeEntryName refuses it - which bounds the residual per-node cost neither pass can remove:
// placing a node means keying it by its full path.
//
// The budget below is enormous next to the ~0.1s this takes: it guards against an order-of-magnitude
// regression, not a few percent.
func Test_deepEntryPathsStayAffordable(t *testing.T) {
	if testing.Short() {
		t.Skip("timing guard")
	}

	names := make([]string, 400)
	for i := range names {
		names[i] = fmt.Sprintf("%s%04d.txt", strings.Repeat("a/", (maxEntryPathBytes-16)/2), i)
	}

	store := storeOf(t, names)
	started := time.Now()
	index, err := NewFromArchiveEntries("", "outer.jar", store, nil)
	require.NoError(t, err)
	took := time.Since(started)

	require.Equal(t, len(names), index.Records())
	assert.Less(t, took, 30*time.Second, "placing deep paths has regressed by an order of magnitude")
	t.Logf("indexed %d entries of %d bytes of path in %s", len(names), len(names[0]), took)
}

// Test_indexTruncatesWhenTheBudgetRefuses covers what an index does when the budget runs out part way
// through: it keeps what it has, says so, and stays usable.
func Test_indexTruncatesWhenTheBudgetRefuses(t *testing.T) {
	names := make([]string, 500)
	for i := range names {
		names[i] = fmt.Sprintf("dir/file%04d.txt", i)
	}

	// room for a handful of entries, nowhere near all 500
	limiter := archive.NewLimiter(archive.Limits{MaxMemoryBytes: 10 * indexNodeCost, MaxDiskBytes: 0})
	index, err := NewFromArchiveEntries("", "outer.jar", storeOf(t, names), limiter.Charge())
	require.NoError(t, err)

	assert.True(t, index.Truncated(), "the budget refused a record, so the index is truncated")
	assert.Positive(t, index.Records(), "what was indexed before the refusal is kept")
	assert.Less(t, index.Records(), len(names))

	// and what it did index is a working filesystem, not a half-built one
	locations, err := index.FilesByGlob("**/*.txt")
	require.NoError(t, err)
	assert.Len(t, locations, index.Records())
	for _, loc := range locations {
		assert.True(t, index.HasPath("/"+loc.RealPath))
	}
}

// Test_zeroMemoryBudgetStillIndexes covers why index records fall back to the disk budget:
// MaxMemoryBytes of zero is a supported configuration meaning "spill everything", and an archive must
// still be reachable under it.
func Test_zeroMemoryBudgetStillIndexes(t *testing.T) {
	limiter := archive.NewLimiter(archive.Limits{MaxMemoryBytes: 0, MaxDiskBytes: -1})
	index, err := NewFromArchiveEntries("", "outer.jar",
		storeOf(t, []string{"a/b/c.txt", "a/d.txt"}), limiter.Charge())
	require.NoError(t, err)

	assert.False(t, index.Truncated())
	assert.Equal(t, 2, index.Records())

	memory, disk := limiter.InUse()
	assert.Zero(t, memory, "a zero memory budget admits nothing to memory")
	assert.Positive(t, disk, "so the index records are charged against the disk budget instead")
}

// storeOf puts the given entry names into a store with no budget of its own, so what a test measures
// afterwards is the index's charge and nothing else.
func storeOf(t testing.TB, names []string) *archive.EntryStore {
	t.Helper()
	workDir := archive.NewWorkDir(tmpdir.WithValue(context.Background(), tmpdir.FromPath(t.TempDir())))
	t.Cleanup(workDir.Remove)
	store := archive.NewEntryStore(workDir, "test.jar", nil)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	for _, name := range names {
		hdr := tar.Header{Name: name, Mode: 0o600, Typeflag: tar.TypeReg}
		_, err := store.Add(hdr, strings.NewReader(""), nil)
		require.NoError(t, err)
	}
	return store
}

func unboundedCharge() (*archive.Limiter, *archive.Charge) {
	limiter := archive.NewLimiter(archive.Limits{MaxMemoryBytes: -1, MaxDiskBytes: -1})
	return limiter, limiter.Charge()
}

// heapGrowth reports how much live heap build left behind, which for an index kept alive is what it
// retains.
func heapGrowth(t testing.TB, build func()) int64 {
	t.Helper()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&before)

	build()

	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&after)
	return int64(after.HeapAlloc) - int64(before.HeapAlloc)
}
