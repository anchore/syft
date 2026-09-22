package archive

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAcquireContent_randomAccessReadersAreUsedInPlace(t *testing.T) {
	workDir := t.TempDir()
	charge := NewLimiter(Limits{MaxMemoryBytes: 0, MaxDiskBytes: 0}).Charge()
	reader := bytes.NewReader([]byte("already random access"))

	content, err := acquireContent(reader, "app.zip", WorkDirAt(workDir), charge)
	require.NoError(t, err)

	assert.Same(t, reader, content.ReaderAtSeeker)
	assert.Empty(t, filesIn(t, workDir))
	mem, disk := charge.held()
	assert.Zero(t, mem, "nothing is held, so nothing is charged")
	assert.Zero(t, disk)
	content.Release()
}

func TestHoldContent_heldWhileTheLimitAdmitsIt(t *testing.T) {
	workDir := t.TempDir()
	body := []byte(strings.Repeat("a", 100))
	charge := NewLimiter(Limits{MaxMemoryBytes: 1000, MaxDiskBytes: 1000}).Charge()

	content, err := holdContent(bytes.NewReader(body), "app.zip", WorkDirAt(workDir), charge)
	require.NoError(t, err)

	assert.Equal(t, body, readAll(t, content))
	assert.Empty(t, filesIn(t, workDir))
	mem, disk := charge.held()
	assert.Equal(t, int64(100), mem)
	assert.Zero(t, disk)

	content.Release()
	mem, _ = charge.held()
	assert.Zero(t, mem, "releasing held content refunds its memory")
}

func TestHoldContent_writtenToDiskWhenTheLimitDoesNotAdmitIt(t *testing.T) {
	workDir := t.TempDir()
	body := []byte(strings.Repeat("b", 250))
	charge := NewLimiter(Limits{MaxMemoryBytes: 100, MaxDiskBytes: 10_000}).Charge()

	content, err := holdContent(bytes.NewReader(body), "app.zip", WorkDirAt(workDir), charge)
	require.NoError(t, err)

	assert.Equal(t, []string{contentFileName}, filesIn(t, workDir))
	assert.Equal(t, body, readAll(t, content), "the bytes read before the limit refused must not be lost")
	mem, disk := charge.held()
	assert.Zero(t, mem, "nothing stays charged to a limit that refused")
	assert.Equal(t, int64(250), disk)

	content.Release()
	assert.Empty(t, filesIn(t, workDir), "releasing removes the file")
	_, disk = charge.held()
	assert.Zero(t, disk, "and refunds it")
}

// peakTrackingReader records the highest memory charge observed while being read.
type peakTrackingReader struct {
	r      io.Reader
	charge *Charge
	peak   int64
}

func (p *peakTrackingReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if mem, _ := p.charge.held(); mem > p.peak {
		p.peak = mem
	}
	return n, err
}

func TestHoldContent_largeArchiveNeverBuffersBeyondTheLimit(t *testing.T) {
	workDir := t.TempDir()
	const limit = int64(3 * copyChunkSize)
	body := []byte(strings.Repeat("c", 10*copyChunkSize))
	charge := NewLimiter(Limits{MaxMemoryBytes: limit, MaxDiskBytes: int64(len(body)) + 1}).Charge()
	tracked := &peakTrackingReader{r: bytes.NewReader(body), charge: charge}

	content, err := holdContent(tracked, "app.zip", WorkDirAt(workDir), charge)
	require.NoError(t, err)
	t.Cleanup(content.Release)

	assert.Equal(t, []string{contentFileName}, filesIn(t, workDir))
	assert.Equal(t, body, readAll(t, content))
	assert.LessOrEqual(t, tracked.peak, limit, "memory charged must never exceed the limit, even transiently")
	mem, disk := charge.held()
	assert.Zero(t, mem)
	assert.Equal(t, int64(len(body)), disk)
}

func TestHoldContent_diskLimitIsTerminal(t *testing.T) {
	tests := []struct {
		name   string
		limits Limits
	}{
		{"a disk limit that is exceeded", Limits{MaxDiskBytes: 100}},
		{"a zero disk limit", Limits{MaxMemoryBytes: 10, MaxDiskBytes: 0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			workDir := t.TempDir()
			charge := NewLimiter(tt.limits).Charge()

			_, err := holdContent(bytes.NewReader([]byte(strings.Repeat("d", 500))), "app.zip", WorkDirAt(workDir), charge)
			require.ErrorIs(t, err, ErrDiskLimitReached)

			assert.Empty(t, filesIn(t, workDir), "the partial file must not be left behind")
			mem, disk := charge.held()
			assert.Zero(t, mem)
			assert.Zero(t, disk, "bytes no longer on disk must be refunded")
		})
	}
}

func TestHoldContent_threeStateLimits(t *testing.T) {
	body := []byte(strings.Repeat("e", 500))

	t.Run("a zero memory limit sends everything to disk", func(t *testing.T) {
		workDir := t.TempDir()
		charge := NewLimiter(Limits{MaxMemoryBytes: 0, MaxDiskBytes: 10_000}).Charge()

		content, err := holdContent(bytes.NewReader(body), "app.zip", WorkDirAt(workDir), charge)
		require.NoError(t, err)
		t.Cleanup(content.Release)

		assert.Equal(t, []string{contentFileName}, filesIn(t, workDir))
		mem, disk := charge.held()
		assert.Zero(t, mem)
		assert.Equal(t, int64(500), disk)
	})

	t.Run("a negative memory limit holds content regardless of how much is already held", func(t *testing.T) {
		workDir := t.TempDir()
		charge := NewLimiter(Limits{MaxMemoryBytes: -1, MaxDiskBytes: 10_000}).Charge()
		require.True(t, charge.Memory(1_000_000))

		content, err := holdContent(bytes.NewReader(body), "app.zip", WorkDirAt(workDir), charge)
		require.NoError(t, err)
		t.Cleanup(content.Release)

		assert.Empty(t, filesIn(t, workDir))
		mem, disk := charge.held()
		assert.Equal(t, int64(1_000_000+len(body)), mem)
		assert.Zero(t, disk)
	})

	t.Run("a zero disk limit still holds what memory admits", func(t *testing.T) {
		workDir := t.TempDir()
		charge := NewLimiter(Limits{MaxMemoryBytes: 10_000, MaxDiskBytes: 0}).Charge()

		content, err := holdContent(bytes.NewReader(body), "app.zip", WorkDirAt(workDir), charge)
		require.NoError(t, err)
		t.Cleanup(content.Release)

		assert.Empty(t, filesIn(t, workDir))
		mem, disk := charge.held()
		assert.Equal(t, int64(len(body)), mem)
		assert.Zero(t, disk)
	})

	t.Run("a negative disk limit writes with no ceiling", func(t *testing.T) {
		workDir := t.TempDir()
		charge := NewLimiter(Limits{MaxMemoryBytes: 0, MaxDiskBytes: -1}).Charge()

		content, err := holdContent(bytes.NewReader(body), "app.zip", WorkDirAt(workDir), charge)
		require.NoError(t, err)
		t.Cleanup(content.Release)

		assert.Equal(t, []string{contentFileName}, filesIn(t, workDir))
		assert.Equal(t, body, readAll(t, content))
	})
}

func TestHoldContent_nilChargeHoldsEverythingInMemory(t *testing.T) {
	workDir := t.TempDir()
	body := []byte("small enough")

	content, err := holdContent(bytes.NewReader(body), "app.zip", WorkDirAt(workDir), nil)
	require.NoError(t, err)
	t.Cleanup(content.Release)

	assert.Equal(t, body, readAll(t, content))
	assert.Empty(t, filesIn(t, workDir))
}

func readAll(t *testing.T, c Content) []byte {
	t.Helper()
	_, err := c.Seek(0, io.SeekStart)
	require.NoError(t, err)
	body, err := io.ReadAll(c)
	require.NoError(t, err)
	return body
}
