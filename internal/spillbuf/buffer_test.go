package spillbuf

import (
	"bytes"
	"errors"
	"io"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/tmpdir"
)

func newTestBuffer(t *testing.T, opts ...Option) *Buffer {
	t.Helper()
	b := New(tmpdir.FromPath(t.TempDir()), opts...)
	t.Cleanup(func() { _ = b.Close() })
	return b
}

func mustWrite(t *testing.T, b *Buffer, off int64, p []byte) {
	t.Helper()
	n, err := b.WriteAt(p, off)
	require.NoError(t, err)
	require.Equal(t, len(p), n, "WriteAt must report the full write")
}

// readAll returns everything the buffer is willing to hand back.
func readAll(t *testing.T, b *Buffer) []byte {
	t.Helper()
	out := make([]byte, b.Size())
	if len(out) == 0 {
		return nil
	}
	n, err := b.ReadAt(out, 0)
	require.NoError(t, err, "a read of exactly Size bytes is not short")
	require.Equal(t, len(out), n)
	return out
}

func repeat(b byte, n int) []byte { return bytes.Repeat([]byte{b}, n) }

// --- the core property: report only what was stored -------------------------------------------------

// TestSizeIsTheContiguousPrefix is the property the package exists for. A sparse buffer hands its holes
// back as zeros it never stored, so reporting a length that covers them lets a write offset stand in for
// real output: whatever sizes an allocation against this reader then allocates bytes nothing produced.
func TestSizeIsTheContiguousPrefix(t *testing.T) {
	tests := []struct {
		name     string
		writes   []extent // start is the offset, end-start the length
		wantSize int64
	}{
		{
			name:     "nothing written",
			wantSize: 0,
		},
		{
			name:     "one run from zero",
			writes:   []extent{{0, 100}},
			wantSize: 100,
		},
		{
			name:     "a run that does not start at zero covers nothing",
			writes:   []extent{{10, 100}},
			wantSize: 0,
		},
		{
			name:     "adjacent runs join",
			writes:   []extent{{0, 50}, {50, 100}},
			wantSize: 100,
		},
		{
			name:     "a hole stops the prefix",
			writes:   []extent{{0, 50}, {60, 100}},
			wantSize: 50,
		},
		{
			name:     "the hole is filled later",
			writes:   []extent{{0, 50}, {60, 100}, {50, 60}},
			wantSize: 100,
		},
		{
			name:     "out of order still resolves",
			writes:   []extent{{60, 100}, {0, 50}, {50, 60}},
			wantSize: 100,
		},
		{
			name:     "overlapping runs",
			writes:   []extent{{0, 60}, {40, 100}},
			wantSize: 100,
		},
		{
			name:     "a run fully inside another",
			writes:   []extent{{0, 100}, {20, 40}},
			wantSize: 100,
		},
		{
			name:     "far placement is not coverage",
			writes:   []extent{{0, 64}, {1 << 20, 1<<20 + 64}},
			wantSize: 64,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := newTestBuffer(t)
			for _, w := range tt.writes {
				mustWrite(t, b, w.start, repeat('x', int(w.end-w.start)))
			}
			assert.Equal(t, tt.wantSize, b.Size(), "Size is the contiguous prefix")
		})
	}
}

// TestReadPastSizeIsEOFNotZeros is the other half of the same property. Sparse storage returns zeros for
// a hole for free; handing those out would make the hole indistinguishable from real content.
func TestReadPastSizeIsEOFNotZeros(t *testing.T) {
	b := newTestBuffer(t)
	mustWrite(t, b, 0, repeat('A', 64))
	mustWrite(t, b, 4096, repeat('B', 64)) // past a hole

	require.Equal(t, int64(64), b.Size())

	t.Run("a read starting in the hole is EOF", func(t *testing.T) {
		p := make([]byte, 16)
		n, err := b.ReadAt(p, 100)
		assert.Zero(t, n)
		assert.ErrorIs(t, err, io.EOF)
	})

	t.Run("a read starting at the far extent is EOF, not the bytes there", func(t *testing.T) {
		p := make([]byte, 64)
		n, err := b.ReadAt(p, 4096)
		assert.Zero(t, n)
		assert.ErrorIs(t, err, io.EOF)
		assert.Equal(t, make([]byte, 64), p, "nothing may be copied out")
	})

	t.Run("a read running off the end is short and says so", func(t *testing.T) {
		p := make([]byte, 128)
		n, err := b.ReadAt(p, 0)
		assert.Equal(t, 64, n, "only the stored prefix comes back")
		assert.ErrorIs(t, err, io.EOF)
		assert.Equal(t, repeat('A', 64), p[:64])
		assert.Equal(t, make([]byte, 64), p[64:], "the rest is untouched")
	})
}

// TestSparsePlacementIsNotAnAllocationKnob pins the amplification directly: a tiny payload parked at a
// huge offset must not cost memory proportional to the offset.
func TestSparsePlacementIsNotAnAllocationKnob(t *testing.T) {
	const far = 512 << 20 // 512MB out

	b := newTestBuffer(t, WithMemLimit(1<<20))
	mustWrite(t, b, 0, repeat('A', 64))

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	mustWrite(t, b, far, repeat('B', 64))
	runtime.ReadMemStats(&after)

	allocated := after.TotalAlloc - before.TotalAlloc
	t.Logf("writing 64 bytes at offset %d allocated %d bytes", far, allocated)
	assert.Less(t, allocated, uint64(1<<20),
		"a far placement must cost its own bytes, not its offset")
	assert.Equal(t, int64(64), b.Size(), "and it must not count toward what the buffer will deliver")
}

// --- tiers ------------------------------------------------------------------------------------------

func TestMemoryTierNeverTouchesDisk(t *testing.T) {
	dir := t.TempDir()
	b := New(tmpdir.FromPath(dir), WithMemLimit(4096))
	t.Cleanup(func() { _ = b.Close() })

	mustWrite(t, b, 0, repeat('A', 4096)) // exactly the limit

	assert.Equal(t, repeat('A', 4096), readAll(t, b))
	assert.Nil(t, b.file, "a buffer that stays inside the limit must not create a file")
	assert.Empty(t, dirEntries(t, dir), "and must leave nothing on disk")
}

func TestSpillCreatesTheFileOnlyWhenNeeded(t *testing.T) {
	dir := t.TempDir()
	b := New(tmpdir.FromPath(dir), WithMemLimit(4096))
	t.Cleanup(func() { _ = b.Close() })

	mustWrite(t, b, 0, repeat('A', 4096))
	require.Empty(t, dirEntries(t, dir))

	mustWrite(t, b, 4096, repeat('B', 1)) // one byte past the limit
	assert.NotNil(t, b.file)
	assert.Len(t, dirEntries(t, dir), 1, "exactly one spill file")
}

func TestWriteStraddlingTheLimit(t *testing.T) {
	const limit = 1024
	b := newTestBuffer(t, WithMemLimit(limit))

	payload := make([]byte, 2048)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	// starts below the limit and ends well past it, so the write is split across both tiers
	mustWrite(t, b, limit-512, payload)

	require.Equal(t, int64(0), b.Size(), "nothing was written at zero yet")
	mustWrite(t, b, 0, repeat('Z', limit-512))

	got := readAll(t, b)
	require.Len(t, got, limit-512+2048)
	assert.Equal(t, repeat('Z', limit-512), got[:limit-512], "the memory-only part")
	assert.Equal(t, payload, got[limit-512:], "the straddling part reads back whole")
}

func TestMemLimitZeroSendsEverythingToDisk(t *testing.T) {
	dir := t.TempDir()
	b := New(tmpdir.FromPath(dir), WithMemLimit(0))
	t.Cleanup(func() { _ = b.Close() })

	mustWrite(t, b, 0, repeat('A', 16))
	assert.Equal(t, repeat('A', 16), readAll(t, b))
	assert.Len(t, dirEntries(t, dir), 1, "with no memory tier the first byte spills")
	assert.Nil(t, b.mem)
}

func TestNegativeMemLimitIsTreatedAsZero(t *testing.T) {
	b := newTestBuffer(t, WithMemLimit(-1))
	mustWrite(t, b, 0, repeat('A', 8))
	assert.Equal(t, repeat('A', 8), readAll(t, b))
}

func TestDefaultMemLimitApplies(t *testing.T) {
	b := New(nil)
	t.Cleanup(func() { _ = b.Close() })
	assert.Equal(t, DefaultMemLimit, b.memLimit)
}

// --- no temp dir ------------------------------------------------------------------------------------

func TestNoTempDir(t *testing.T) {
	t.Run("a write inside the memory limit needs no temp dir", func(t *testing.T) {
		b := New(nil, WithMemLimit(4096))
		t.Cleanup(func() { _ = b.Close() })

		mustWrite(t, b, 0, repeat('A', 4096))
		assert.Equal(t, repeat('A', 4096), readAll(t, b))
	})

	t.Run("a write past it fails rather than allocating", func(t *testing.T) {
		b := New(nil, WithMemLimit(4096))
		t.Cleanup(func() { _ = b.Close() })

		_, err := b.WriteAt(repeat('B', 1), 4096)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNoTempDir)
	})
}

// --- input validation -------------------------------------------------------------------------------

func TestWriteAtRejectsBadInput(t *testing.T) {
	b := newTestBuffer(t)

	t.Run("negative offset", func(t *testing.T) {
		_, err := b.WriteAt([]byte("x"), -1)
		assert.Error(t, err)
	})

	t.Run("an offset plus length that would overflow", func(t *testing.T) {
		_, err := b.WriteAt(repeat('x', 16), math.MaxInt64-8)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "overflow",
			"the check must be a subtraction, not off+len wrapping into an in-range end")
	})

	t.Run("an empty write is a no-op, not an extent", func(t *testing.T) {
		n, err := b.WriteAt(nil, 500)
		require.NoError(t, err)
		assert.Zero(t, n)
		assert.Empty(t, b.written, "a zero-length write records nothing")
	})
}

func TestReadAtRejectsBadInput(t *testing.T) {
	b := newTestBuffer(t)
	mustWrite(t, b, 0, repeat('A', 16))

	t.Run("negative offset", func(t *testing.T) {
		_, err := b.ReadAt(make([]byte, 4), -1)
		assert.Error(t, err)
	})

	t.Run("empty read", func(t *testing.T) {
		n, err := b.ReadAt(nil, 0)
		assert.NoError(t, err)
		assert.Zero(t, n)
	})

	t.Run("read from an empty buffer", func(t *testing.T) {
		empty := newTestBuffer(t)
		n, err := empty.ReadAt(make([]byte, 4), 0)
		assert.Zero(t, n)
		assert.ErrorIs(t, err, io.EOF)
	})
}

// TestReadAtHonorsTheReaderAtContract pins what io.ReaderAt requires: a short read must come with a
// non-nil error, and a full read must not invent one. Parsers built on io.ReaderAt (debug/elf among them)
// rely on this to tell "the file ends here" from "try again".
func TestReadAtHonorsTheReaderAtContract(t *testing.T) {
	b := newTestBuffer(t, WithMemLimit(64))
	mustWrite(t, b, 0, repeat('A', 200)) // spans both tiers

	for _, size := range []int{1, 63, 64, 65, 199, 200} {
		p := make([]byte, size)
		n, err := b.ReadAt(p, 0)
		assert.Equal(t, size, n, "size=%d", size)
		assert.NoError(t, err, "a read fully inside the buffer must not report EOF (size=%d)", size)
	}

	p := make([]byte, 201)
	n, err := b.ReadAt(p, 0)
	assert.Equal(t, 200, n)
	assert.ErrorIs(t, err, io.EOF, "one byte past the end is short and must say so")
}

func TestReadAtEveryOffsetAndLength(t *testing.T) {
	const limit = 32
	b := newTestBuffer(t, WithMemLimit(limit))

	want := make([]byte, 100)
	for i := range want {
		want[i] = byte(i)
	}
	mustWrite(t, b, 0, want)

	// every offset x length pair, so a tier-boundary off-by-one cannot hide
	for off := 0; off <= len(want); off++ {
		for l := 0; l <= len(want)-off+2; l++ {
			p := make([]byte, l)
			n, err := b.ReadAt(p, int64(off))

			expected := len(want) - off
			if l < expected {
				expected = l
			}
			assert.Equal(t, expected, n, "off=%d len=%d", off, l)
			assert.Equal(t, want[off:off+expected], p[:expected], "off=%d len=%d", off, l)

			switch {
			case l == 0:
				assert.NoError(t, err, "off=%d len=0", off)
			case off >= len(want):
				assert.ErrorIs(t, err, io.EOF, "off=%d len=%d", off, l)
			case l > expected:
				assert.ErrorIs(t, err, io.EOF, "off=%d len=%d", off, l)
			default:
				assert.NoError(t, err, "off=%d len=%d", off, l)
			}
		}
	}
}

// --- overwrite semantics ----------------------------------------------------------------------------

func TestOverwrite(t *testing.T) {
	tests := []struct {
		name     string
		memLimit int64
	}{
		{"in memory", 1 << 20},
		{"on disk", 0},
		{"across the boundary", 8},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := newTestBuffer(t, WithMemLimit(tt.memLimit))
			mustWrite(t, b, 0, repeat('A', 16))
			mustWrite(t, b, 4, repeat('B', 8))

			want := append(append(repeat('A', 4), repeat('B', 8)...), repeat('A', 4)...)
			assert.Equal(t, want, readAll(t, b), "the later write wins over the range it covers")
			assert.Equal(t, int64(16), b.Size(), "an overwrite does not extend the buffer")
		})
	}
}

// --- extents ----------------------------------------------------------------------------------------

func TestWrittenExtentsAreSortedAndMerged(t *testing.T) {
	tests := []struct {
		name   string
		writes []extent
		want   []extent
	}{
		{
			name:   "disjoint stay separate, in order",
			writes: []extent{{100, 150}, {0, 50}},
			want:   []extent{{0, 50}, {100, 150}},
		},
		{
			name:   "adjacent merge",
			writes: []extent{{0, 50}, {50, 100}},
			want:   []extent{{0, 100}},
		},
		{
			name:   "overlapping merge",
			writes: []extent{{0, 60}, {40, 100}},
			want:   []extent{{0, 100}},
		},
		{
			name:   "a write bridging two runs collapses all three",
			writes: []extent{{0, 20}, {80, 100}, {20, 80}},
			want:   []extent{{0, 100}},
		},
		{
			name:   "a contained write changes nothing",
			writes: []extent{{0, 100}, {20, 40}},
			want:   []extent{{0, 100}},
		},
		{
			name:   "identical writes collapse",
			writes: []extent{{0, 10}, {0, 10}, {0, 10}},
			want:   []extent{{0, 10}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := newTestBuffer(t)
			for _, w := range tt.writes {
				mustWrite(t, b, w.start, repeat('x', int(w.end-w.start)))
			}
			assert.Equal(t, tt.want, b.written)
		})
	}
}

func TestWrittenExtentsStayCompactUnderManyAdjacentWrites(t *testing.T) {
	b := newTestBuffer(t)
	for i := int64(0); i < 1000; i++ {
		mustWrite(t, b, i*8, repeat('A', 8))
	}
	assert.Len(t, b.written, 1, "a run of adjacent writes must collapse to one extent, not 1000")
	assert.Equal(t, int64(8000), b.Size())
}

// --- lifecycle --------------------------------------------------------------------------------------

func TestCloseRemovesTheSpillFile(t *testing.T) {
	dir := t.TempDir()
	b := New(tmpdir.FromPath(dir), WithMemLimit(0))
	mustWrite(t, b, 0, repeat('A', 32))
	require.Len(t, dirEntries(t, dir), 1)

	require.NoError(t, b.Close())
	assert.Empty(t, dirEntries(t, dir), "Close must take the spill file with it")
}

func TestCloseIsIdempotent(t *testing.T) {
	b := New(tmpdir.FromPath(t.TempDir()), WithMemLimit(0))
	mustWrite(t, b, 0, repeat('A', 32))

	require.NoError(t, b.Close())
	assert.NoError(t, b.Close(), "a second Close is a no-op, not a double-close")
	assert.NoError(t, b.Close())
}

func TestCloseOnNilReceiver(t *testing.T) {
	var b *Buffer
	assert.NotPanics(t, func() {
		assert.NoError(t, b.Close())
	})
}

func TestCloseWithoutASpillFile(t *testing.T) {
	b := New(nil, WithMemLimit(1<<20))
	mustWrite(t, b, 0, repeat('A', 32))
	assert.NoError(t, b.Close(), "a memory-only buffer closes cleanly with no file to remove")
}

func TestWriteAfterCloseFails(t *testing.T) {
	b := New(tmpdir.FromPath(t.TempDir()))
	mustWrite(t, b, 0, repeat('A', 8))
	require.NoError(t, b.Close())

	_, err := b.WriteAt(repeat('B', 8), 0)
	require.Error(t, err, "a closed buffer must refuse writes rather than resurrect its file")
	assert.ErrorIs(t, err, os.ErrClosed)
}

// TestReadAfterCloseFails pins that a closed buffer reads as closed rather than as empty. Close drops the
// extents, so without the check every read would come back io.EOF and a caller could not tell a buffer it
// still owns from one somebody already released.
func TestReadAfterCloseFails(t *testing.T) {
	b := New(tmpdir.FromPath(t.TempDir()))
	mustWrite(t, b, 0, repeat('A', 8))
	require.NoError(t, b.Close())

	n, err := b.ReadAt(make([]byte, 8), 0)
	assert.Zero(t, n)
	assert.ErrorIs(t, err, os.ErrClosed)

	at, ok := b.FirstGap(8, 100)
	assert.False(t, ok, "and a closed buffer offers nowhere to write")
	assert.Zero(t, at)
}

// TestWriteFailureLeavesTheBufferUnchanged pins the ordering inside WriteAt: the fallible half runs first,
// so a spill file that cannot be created does not take the memory tier down with it.
func TestWriteFailureLeavesTheBufferUnchanged(t *testing.T) {
	// FromPath takes the directory as given, so a path that does not exist makes file creation fail
	b := New(tmpdir.FromPath(filepath.Join(t.TempDir(), "no-such-dir")), WithMemLimit(16))
	t.Cleanup(func() { _ = b.Close() })

	mustWrite(t, b, 0, repeat('A', 8))

	_, err := b.WriteAt(repeat('B', 32), 0) // straddles the limit, so it needs the spill file
	require.Error(t, err)

	assert.Equal(t, int64(8), b.Size(), "a failed write records nothing")
	assert.Nil(t, b.file, "and leaves no half-made spill file behind")

	p := make([]byte, 8)
	n, err := b.ReadAt(p, 0)
	require.NoError(t, err)
	require.Equal(t, 8, n)
	assert.Equal(t, repeat('A', 8), p, "the memory tier still holds what it held")

	mustWrite(t, b, 8, repeat('C', 8)) // inside the limit, so it still needs no file
	assert.Equal(t, append(repeat('A', 8), repeat('C', 8)...), readAll(t, b))
}

// --- interface compliance ---------------------------------------------------------------------------

func TestBufferSatisfiesTheStandardInterfaces(t *testing.T) {
	b := newTestBuffer(t)
	var (
		_ io.WriterAt = b
		_ io.ReaderAt = b
		_ io.Closer   = b
	)
	assert.Implements(t, (*io.ReaderAt)(nil), b)
	assert.Implements(t, (*io.WriterAt)(nil), b)
}

// TestWorksThroughIOOffsetWriter pins the composition every consumer uses: stream a decoded block into
// the buffer at a chosen offset without the writer knowing where it lands.
func TestWorksThroughIOOffsetWriter(t *testing.T) {
	b := newTestBuffer(t, WithMemLimit(16))

	w := io.NewOffsetWriter(b, 8)
	n, err := io.Copy(w, bytes.NewReader(repeat('B', 32)))
	require.NoError(t, err)
	require.Equal(t, int64(32), n)

	mustWrite(t, b, 0, repeat('A', 8))

	got := readAll(t, b)
	assert.Equal(t, append(repeat('A', 8), repeat('B', 32)...), got)
}

// TestWorksWithIOSectionReader pins the other direction: parsers wrap an io.ReaderAt in a SectionReader,
// and it must see a consistent length.
func TestWorksWithIOSectionReader(t *testing.T) {
	b := newTestBuffer(t)
	mustWrite(t, b, 0, repeat('A', 100))

	sr := io.NewSectionReader(b, 0, b.Size())
	got, err := io.ReadAll(sr)
	require.NoError(t, err)
	assert.Equal(t, repeat('A', 100), got)
}

// --- model-based randomized testing -----------------------------------------------------------------

// TestAgainstAReferenceModel drives random writes through the buffer and a dumb reference at the same
// time, then compares every readable byte. This is what catches tier-boundary and merge bugs that
// hand-written cases miss.
func TestAgainstAReferenceModel(t *testing.T) {
	const universe = 8192

	for _, limit := range []int64{0, 1, 64, 1000, 4096, universe * 2} {
		t.Run("memLimit="+itoa(limit), func(t *testing.T) {
			for seed := int64(0); seed < 40; seed++ {
				rng := rand.New(rand.NewSource(seed)) //nolint:gosec // deterministic test input, not crypto
				b := newTestBuffer(t, WithMemLimit(limit))

				model := make([]byte, universe)
				written := make([]bool, universe)

				for op := 0; op < 40; op++ {
					off := rng.Int63n(universe)
					l := rng.Int63n(256) + 1
					if off+l > universe {
						l = universe - off
					}
					payload := make([]byte, l)
					for i := range payload {
						payload[i] = byte(rng.Intn(256))
					}

					mustWrite(t, b, off, payload)
					copy(model[off:], payload)
					for i := off; i < off+l; i++ {
						written[i] = true
					}
				}

				// the reference contiguous prefix
				var want int64
				for want < universe && written[want] {
					want++
				}

				require.Equal(t, want, b.Size(), "seed=%d limit=%d", seed, limit)
				if want == 0 {
					continue
				}
				assert.Equal(t, model[:want], readAll(t, b), "seed=%d limit=%d", seed, limit)
			}
		})
	}
}

// TestRandomReadsMatchTheModel checks partial reads at arbitrary offsets, which the whole-buffer
// comparison above cannot reach.
func TestRandomReadsMatchTheModel(t *testing.T) {
	rng := rand.New(rand.NewSource(7)) //nolint:gosec // deterministic test input, not crypto
	b := newTestBuffer(t, WithMemLimit(97))

	model := make([]byte, 1000)
	for i := range model {
		model[i] = byte(rng.Intn(256))
	}
	// written in random-sized chunks, in order, so the whole range is covered
	for off := 0; off < len(model); {
		l := rng.Intn(50) + 1
		if off+l > len(model) {
			l = len(model) - off
		}
		mustWrite(t, b, int64(off), model[off:off+l])
		off += l
	}
	require.Equal(t, int64(len(model)), b.Size())

	for i := 0; i < 500; i++ {
		off := rng.Intn(len(model))
		l := rng.Intn(len(model)-off) + 1
		p := make([]byte, l)
		n, err := b.ReadAt(p, int64(off))
		require.NoError(t, err)
		require.Equal(t, l, n)
		require.Equal(t, model[off:off+l], p, "off=%d len=%d", off, l)
	}
}

// --- helpers ----------------------------------------------------------------------------------------

func dirEntries(t *testing.T, dir string) []os.DirEntry {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	require.NoError(t, err)

	// tmpdir.NewFile creates the spill file inside the root it is given
	var files []os.DirEntry
	for _, e := range entries {
		if e.IsDir() {
			sub, err := os.ReadDir(filepath.Join(dir, e.Name()))
			require.NoError(t, err)
			for _, s := range sub {
				files = append(files, s)
			}
			continue
		}
		files = append(files, e)
	}
	return files
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// TestMemoryTierGrowsAmortized is the regression test for quadratic growth. Sizing the tier to exactly
// what each write needs reallocates and copies the whole thing per call, so a caller streaming a block in
// small chunks (which is what io.Copy through an OffsetWriter does) pays O(n^2): filling a 1MB tier in
// 32KB chunks cost ~16MB of allocation and showed up as a 19MB spike decompressing a 16MB payload.
func TestMemoryTierGrowsAmortized(t *testing.T) {
	const (
		limit = 1 << 20
		chunk = 32 << 10
	)
	b := newTestBuffer(t, WithMemLimit(limit))

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for off := int64(0); off < limit; off += chunk {
		mustWrite(t, b, off, repeat('A', chunk))
	}
	runtime.ReadMemStats(&after)

	allocated := after.TotalAlloc - before.TotalAlloc
	t.Logf("filling a %d byte tier in %d byte chunks allocated %d bytes", limit, chunk, allocated)
	assert.Less(t, allocated, uint64(4*limit),
		"growth has to be amortized, not a fresh copy of the whole tier per write")
	assert.Equal(t, int64(limit), b.Size())
}

// TestMemoryTierNeverExceedsTheLimit pins the cap that geometric growth could otherwise overshoot.
func TestMemoryTierNeverExceedsTheLimit(t *testing.T) {
	const limit = 1000
	b := newTestBuffer(t, WithMemLimit(limit))

	for off := int64(0); off < 4*limit; off += 100 {
		mustWrite(t, b, off, repeat('A', 100))
		assert.LessOrEqual(t, int64(len(b.mem)), int64(limit),
			"the memory tier may never grow past its own limit (off=%d)", off)
	}
	assert.Equal(t, int64(4*limit), b.Size())
}

// TestFirstGap covers the placement question a caller writing at offsets of its own choosing has to ask.
// It moved here from the UPX cataloger, which used to walk an exported extent list to answer it itself.
func TestFirstGap(t *testing.T) {
	tests := []struct {
		name   string
		writes []extent
		size   int64
		within int64
		wantAt int64
		wantOK bool
	}{
		{
			name:   "an empty buffer starts at zero",
			size:   16,
			within: 100,
			wantAt: 0, wantOK: true,
		},
		{
			name:   "the gap between two runs comes first",
			writes: []extent{{0, 1000}, {1016, 2000}},
			size:   16,
			within: 3000,
			wantAt: 1000, wantOK: true,
		},
		{
			name:   "with the gap filled the tail is what is left",
			writes: []extent{{0, 2000}},
			size:   1000,
			within: 3000,
			wantAt: 2000, wantOK: true,
		},
		{
			name:   "a gap too small is skipped for a later one",
			writes: []extent{{0, 100}, {108, 200}},
			size:   50,
			within: 1000,
			wantAt: 200, wantOK: true,
		},
		{
			name:   "nowhere left to fit is reported rather than squeezed in",
			writes: []extent{{0, 1000}, {1016, 2000}},
			size:   1001,
			within: 3000,
			wantOK: false,
		},
		{
			name:   "a run past the declared total must not wrap the remaining-space subtraction",
			writes: []extent{{0, 200}},
			size:   8,
			within: 100,
			wantOK: false,
		},
		{
			name:   "exactly filling the tail is allowed",
			writes: []extent{{0, 900}},
			size:   100,
			within: 1000,
			wantAt: 900, wantOK: true,
		},
		{
			name:   "a gap between two runs is still cut off by the bound",
			writes: []extent{{0, 10}, {1000, 1010}},
			size:   45,
			within: 50,
			wantOK: false,
		},
		{
			name:   "a gap between two runs that the bound still leaves room in",
			writes: []extent{{0, 10}, {1000, 1010}},
			size:   30,
			within: 50,
			wantAt: 10, wantOK: true,
		},
		{
			name:   "a negative size is refused rather than treated as zero",
			size:   -1,
			within: 100,
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := newTestBuffer(t)
			for _, w := range tt.writes {
				mustWrite(t, b, w.start, repeat('x', int(w.end-w.start)))
			}

			at, ok := b.FirstGap(tt.size, tt.within)
			assert.Equal(t, tt.wantOK, ok)
			if tt.wantOK {
				assert.Equal(t, tt.wantAt, at)
			}
		})
	}
}

// TestFirstGapNeverOverlapsWhatWasWritten is the property behind the table: whatever offset comes back has
// to be usable, so writing size bytes there must not land on top of anything already stored.
func TestFirstGapNeverOverlapsWhatWasWritten(t *testing.T) {
	rng := rand.New(rand.NewSource(11)) //nolint:gosec // deterministic test input, not crypto
	const universe = 4096

	for seed := 0; seed < 200; seed++ {
		b := newTestBuffer(t)
		occupied := make([]bool, universe)

		for op := 0; op < 6; op++ {
			// deliberately reaches past universe too, so the bound has to cut a between-extents gap short
			off := rng.Int63n(2 * universe)
			l := rng.Int63n(200) + 1
			mustWrite(t, b, off, repeat('x', int(l)))
			for i := off; i < off+l && i < universe; i++ {
				occupied[i] = true
			}
		}

		size := rng.Int63n(100) + 1
		at, ok := b.FirstGap(size, universe)
		if !ok {
			continue
		}
		require.LessOrEqual(t, at+size, int64(universe), "the result must fit inside the declared total")
		for i := at; i < at+size; i++ {
			require.False(t, occupied[i], "FirstGap returned %d for %d bytes, but %d is taken", at, size, i)
		}
	}
}
