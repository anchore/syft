package archive

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolver_put_holdsSmallContentInMemory(t *testing.T) {
	s, dir := resolverIn(t, memCharge(1024))

	var b blob
	require.NoError(t, s.put(&b, bytes.NewReader([]byte("hello"))))

	assert.Equal(t, int64(5), s.heldInMemory())
	assert.Empty(t, filesIn(t, dir))
	assert.Equal(t, "hello", readEntry(t, s.open(&b)))
}

func TestResolver_put_spillsToDiskAndKeepsTheSameBlobs(t *testing.T) {
	// nodes pointing at a blob are not rebuilt when its content moves
	s, dir := resolverIn(t, memCharge(8))

	var first, second blob
	require.NoError(t, s.put(&first, bytes.NewReader([]byte("aaaa"))))
	require.Equal(t, int64(4), s.heldInMemory())

	require.NoError(t, s.put(&second, bytes.NewReader([]byte("bbbbbb"))))

	assert.Zero(t, s.heldInMemory(), "everything moves out, not just the blob that did not fit")
	assert.NotEmpty(t, spillFile(t, dir))
	assert.Equal(t, int64(10), s.written)
	assert.Equal(t, "aaaa", readEntry(t, s.open(&first)))
	assert.Equal(t, "bbbbbb", readEntry(t, s.open(&second)))
}

func TestResolver_put_threeStateLimits(t *testing.T) {
	body := []byte(strings.Repeat("e", 500))

	t.Run("a zero memory limit sends everything to disk", func(t *testing.T) {
		charge := NewLimiter(Limits{MaxMemoryBytes: 0, MaxDiskBytes: 10_000}).charge()
		s, dir := resolverIn(t, charge)

		var b blob
		require.NoError(t, s.put(&b, bytes.NewReader(body)))

		assert.Zero(t, s.heldInMemory())
		assert.NotEmpty(t, spillFile(t, dir))
		assert.Equal(t, body, []byte(readEntry(t, s.open(&b))))
		mem, disk := charge.held()
		assert.Zero(t, mem)
		assert.Equal(t, int64(500), disk)
	})

	t.Run("a negative memory limit holds content regardless of how much is already held", func(t *testing.T) {
		charge := NewLimiter(Limits{MaxMemoryBytes: -1, MaxDiskBytes: 10_000}).charge()
		require.True(t, charge.memory(1_000_000))
		s, dir := resolverIn(t, charge)

		var b blob
		require.NoError(t, s.put(&b, bytes.NewReader(body)))

		assert.Empty(t, filesIn(t, dir))
		mem, disk := charge.held()
		assert.Equal(t, int64(1_000_000+len(body)), mem)
		assert.Zero(t, disk)
	})

	t.Run("a zero disk limit still holds what memory admits", func(t *testing.T) {
		charge := NewLimiter(Limits{MaxMemoryBytes: 10_000, MaxDiskBytes: 0}).charge()
		s, dir := resolverIn(t, charge)

		var b blob
		require.NoError(t, s.put(&b, bytes.NewReader(body)))

		assert.Empty(t, filesIn(t, dir))
		mem, disk := charge.held()
		assert.Equal(t, int64(len(body)), mem)
		assert.Zero(t, disk)
	})

	t.Run("a negative disk limit writes with no ceiling", func(t *testing.T) {
		s, dir := resolverIn(t, NewLimiter(Limits{MaxMemoryBytes: 0, MaxDiskBytes: -1}).charge())

		var b blob
		require.NoError(t, s.put(&b, bytes.NewReader(body)))

		assert.NotEmpty(t, spillFile(t, dir))
		assert.Equal(t, body, []byte(readEntry(t, s.open(&b))))
	})

	t.Run("a nil charge holds everything in memory", func(t *testing.T) {
		s, dir := resolverIn(t, nil)

		var b blob
		require.NoError(t, s.put(&b, bytes.NewReader(body)))

		assert.Empty(t, filesIn(t, dir))
		assert.Equal(t, body, []byte(readEntry(t, s.open(&b))))
	})
}

func TestResolver_put_bytesReadBeforeTheLimitRefusedAreNotLost(t *testing.T) {
	body := []byte(strings.Repeat("b", 250))
	charge := NewLimiter(Limits{MaxMemoryBytes: 100, MaxDiskBytes: 10_000}).charge()
	s, _ := resolverIn(t, charge)

	var b blob
	require.NoError(t, s.put(&b, bytes.NewReader(body)))

	assert.Equal(t, body, []byte(readEntry(t, s.open(&b))))
	mem, disk := charge.held()
	assert.Zero(t, mem, "nothing stays charged to a limit that refused")
	assert.Equal(t, int64(250), disk)
}

// peakTrackingReader records the highest memory charge observed while being read.
type peakTrackingReader struct {
	r      io.Reader
	charge *charge
	peak   int64
}

func (p *peakTrackingReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if mem, _ := p.charge.held(); mem > p.peak {
		p.peak = mem
	}
	return n, err
}

func TestResolver_put_neverBuffersBeyondTheMemoryLimit(t *testing.T) {
	const limit = int64(3 * copyChunkSize)
	body := []byte(strings.Repeat("c", 10*copyChunkSize))
	charge := NewLimiter(Limits{MaxMemoryBytes: limit, MaxDiskBytes: int64(len(body)) + 1}).charge()
	tracked := &peakTrackingReader{r: bytes.NewReader(body), charge: charge}
	s, _ := resolverIn(t, charge)

	var b blob
	require.NoError(t, s.put(&b, tracked))

	assert.Equal(t, body, []byte(readEntry(t, s.open(&b))))
	assert.LessOrEqual(t, tracked.peak, limit, "memory charged must never exceed the limit, even transiently")
	mem, disk := charge.held()
	assert.Zero(t, mem)
	assert.Equal(t, int64(len(body)), disk)
}

func TestResolver_put_diskLimitIsTerminal(t *testing.T) {
	tests := []struct {
		name   string
		limits Limits
	}{
		{"a disk limit that is exceeded", Limits{MaxDiskBytes: 100}},
		{"a zero disk limit", Limits{MaxMemoryBytes: 10, MaxDiskBytes: 0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			charge := NewLimiter(tt.limits).charge()
			s, dir := resolverIn(t, charge)

			var b blob
			err := s.put(&b, bytes.NewReader([]byte(strings.Repeat("d", 500))))
			require.ErrorIs(t, err, ErrDiskLimitReached)

			s.Cleanup()
			assert.Empty(t, filesIn(t, dir), "cleanup removes the partial file")
			mem, disk := charge.held()
			assert.Zero(t, mem)
			assert.Zero(t, disk, "and refunds it")
		})
	}
}

func TestResolver_cleanupRefundsEverythingAndIsIdempotent(t *testing.T) {
	charge := NewLimiter(Limits{MaxMemoryBytes: 8, MaxDiskBytes: -1}).charge()
	s, dir := resolverIn(t, charge)

	var spilled, held blob
	require.NoError(t, s.put(&spilled, bytes.NewReader([]byte("spilled to disk"))))
	require.NoError(t, s.put(&held, bytes.NewReader([]byte("held"))))
	mem, disk := charge.held()
	require.Equal(t, int64(4), mem)
	require.Equal(t, int64(15), disk)
	require.Equal(t, "held", readEntry(t, s.open(&held)))

	s.Cleanup()

	assert.Empty(t, filesIn(t, dir))
	mem, disk = charge.held()
	assert.Zero(t, mem)
	assert.Zero(t, disk)
	_, err := io.ReadAll(s.open(&spilled))
	assert.Error(t, err, "readers over the spill file are no longer valid")
	s.Cleanup()
	mem, disk = charge.held()
	assert.Zero(t, mem, "a second cleanup refunds nothing twice")
	assert.Zero(t, disk)
}

func TestResolver_put_discardRefundsWhatIsHeldInMemory(t *testing.T) {
	charge := memCharge(1024)
	s, _ := resolverIn(t, charge)

	var keep, drop blob
	require.NoError(t, s.put(&keep, bytes.NewReader([]byte("keep"))))
	require.NoError(t, s.put(&drop, bytes.NewReader([]byte("dropped"))))

	s.discard(&drop)

	mem, _ := charge.held()
	assert.Equal(t, int64(4), mem)
	assert.Equal(t, int64(4), s.heldInMemory())
	assert.Empty(t, readEntry(t, s.open(&drop)))
	assert.Equal(t, "keep", readEntry(t, s.open(&keep)))
}

func TestStorage_filesystemCostDoesNotTrackEntryCount(t *testing.T) {
	small, smallRoot := extractedResolver(t, manyEntryZip(t, 2), spillingLimits)
	large, largeRoot := extractedResolver(t, manyEntryZip(t, 5000), spillingLimits)

	assert.Len(t, filesIn(t, smallRoot), 1)
	assert.Len(t, filesIn(t, largeRoot), 1, "5000 entries cost the same filesystem entries as 2")

	assert.Len(t, small.files, 2)
	assert.Len(t, large.files, 5000)

	// entries cost their content and nothing else on disk: no headers, no padding
	assert.Equal(t, int64(2), small.written)
	assert.Equal(t, int64(5000), large.written)
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

	r, root := extractedResolver(t, buf.Bytes(), spillingLimits)

	body, err := os.ReadFile(filepath.Join(root, spillFile(t, root)))
	require.NoError(t, err)
	offset := int64(bytes.Index(body, []byte(wanted)))
	require.Greater(t, offset, int64(len(body))*9/10, "the last entry must really be at the end of the file")

	n := r.byPath["/zz-last.txt"]
	require.NotNil(t, n)

	reader := r.open(&n.content)
	end, err := reader.Seek(0, io.SeekEnd)
	require.NoError(t, err)
	assert.Equal(t, int64(len(wanted)), end)

	head := make([]byte, 8)
	_, err = reader.ReadAt(head, 0)
	require.NoError(t, err)
	assert.Equal(t, wanted[:8], string(head))
}
