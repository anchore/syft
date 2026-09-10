package archive

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// filesIn lists the regular files directly in dir, which is how a test tells content held in memory
// from content overflowed to disk.
func filesIn(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	return names
}

func readAll(t *testing.T, c Content) []byte {
	t.Helper()
	_, err := c.Reader.Seek(0, io.SeekStart)
	require.NoError(t, err)
	body, err := io.ReadAll(c.Reader)
	require.NoError(t, err)
	return body
}

func TestHoldContent_heldWhileTheLimitAdmitsIt(t *testing.T) {
	// the referent for the memory limit: an archive small enough to hold needs no file on disk at
	// all, where every archive used to be copied to a temp file purely so an extractor could seek it
	workDir := t.TempDir()
	body := []byte(strings.Repeat("a", 100))
	limiter := NewLimiter(Limits{MaxMemoryBytes: 1000, MaxDiskBytes: 1000})
	charge := limiter.Charge()

	held, err := holdContent(bytes.NewReader(body), workDir, "app.zip", charge, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, held.Close()) })

	assert.IsType(t, &bytes.Reader{}, held.Reader)
	assert.Equal(t, body, readAll(t, held))
	assert.Empty(t, filesIn(t, workDir), "content held in memory must write nothing to disk")

	mem, disk := charge.Held()
	assert.Equal(t, int64(100), mem)
	assert.Zero(t, disk)
}

func TestHoldContent_overflowsWhenTheLimitDoesNotAdmitIt(t *testing.T) {
	// where the boundary falls is decided by the memory limit and nothing else: an archive that does
	// not fit overflows in full, and the bytes already read to discover that lead the overflow rather than
	// being lost
	workDir := t.TempDir()
	body := []byte(strings.Repeat("b", 250))
	limiter := NewLimiter(Limits{MaxMemoryBytes: 100, MaxDiskBytes: 10_000})
	charge := limiter.Charge()

	held, err := holdContent(bytes.NewReader(body), workDir, "app.zip", charge, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, held.Close()) })

	assert.Equal(t, []string{"app.zip"}, filesIn(t, workDir))
	assert.Equal(t, body, readAll(t, held),
		"the bytes read to decide the routing must lead the overflow rather than being lost")

	mem, disk := charge.Held()
	assert.Zero(t, mem, "nothing is charged to a limit that refused")
	assert.Equal(t, int64(250), disk)
}

// peakTrackingReader records the highest memory charge observed at any point while reading, which is
// how a test tells that a large archive was never buffered beyond what the limit would admit -
// nothing about the routing decision is otherwise observable from outside holdContent.
type peakTrackingReader struct {
	r      io.Reader
	charge *Charge
	peak   int64
}

func (p *peakTrackingReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if mem, _ := p.charge.Held(); mem > p.peak {
		p.peak = mem
	}
	return n, err
}

func TestHoldContent_largeArchiveNeverBuffersBeyondTheLimit(t *testing.T) {
	// an archive many times the memory limit must overflow, and at no point along the way may more than
	// the limit would admit be held while the routing is being decided - it is never read
	// speculatively into memory that has no room for it
	workDir := t.TempDir()
	const limit = int64(3 * copyChunkSize)
	body := []byte(strings.Repeat("c", 10*copyChunkSize))
	limiter := NewLimiter(Limits{MaxMemoryBytes: limit, MaxDiskBytes: int64(len(body)) + 1})
	charge := limiter.Charge()
	tracked := &peakTrackingReader{r: bytes.NewReader(body), charge: charge}

	held, err := holdContent(tracked, workDir, "app.zip", charge, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, held.Close()) })

	assert.Equal(t, []string{"app.zip"}, filesIn(t, workDir), "an archive this much larger than the limit must overflow")
	assert.Equal(t, body, readAll(t, held))
	assert.LessOrEqual(t, tracked.peak, limit,
		"memory charged must never exceed the limit, even transiently, while routing is decided")

	mem, disk := charge.Held()
	assert.Zero(t, mem)
	assert.Equal(t, int64(len(body)), disk)
}

func TestHoldContent_diskLimitIsTerminal(t *testing.T) {
	// there is nowhere further to overflow, so content that will not fit is refused and the caller skips
	// the archive rather than waiting for capacity that nothing will release
	workDir := t.TempDir()
	body := []byte(strings.Repeat("d", 500))
	limiter := NewLimiter(Limits{MaxDiskBytes: 100})
	charge := limiter.Charge()

	_, err := holdContent(bytes.NewReader(body), workDir, "app.zip", charge, nil)
	require.ErrorIs(t, err, ErrDiskLimitReached)

	assert.Empty(t, filesIn(t, workDir), "the partial overflow must not be left behind")
	mem, disk := charge.Held()
	assert.Zero(t, mem)
	assert.Zero(t, disk, "bytes no longer on disk must be refunded, or the limit only ever rises")
}

func TestHoldContent_zeroDiskLimitSkipsRatherThanFails(t *testing.T) {
	// a zero disk limit has the same outcome as a positive disk limit exceeded: content that will
	// not fit anywhere yields ErrDiskLimitReached so the caller skips the archive, rather than the
	// scan failing
	workDir := t.TempDir()
	body := []byte(strings.Repeat("f", 500))
	limiter := NewLimiter(Limits{MaxMemoryBytes: 10, MaxDiskBytes: 0})
	charge := limiter.Charge()

	_, err := holdContent(bytes.NewReader(body), workDir, "app.zip", charge, nil)
	require.ErrorIs(t, err, ErrDiskLimitReached)

	assert.Empty(t, filesIn(t, workDir), "no partial overflow is left behind")
	mem, disk := charge.Held()
	assert.Zero(t, mem)
	assert.Zero(t, disk)
}

func TestHoldContent_threeStateLimits(t *testing.T) {
	// both limits read positive/zero/negative the same way: positive is the limit, zero means none
	// of that resource at all, negative means unbounded. A caller can bound one without bounding the
	// other.
	body := []byte(strings.Repeat("e", 500))

	t.Run("a zero memory limit sends everything to disk", func(t *testing.T) {
		// zero does not mean unlimited memory: the memory limit decides a routing question rather
		// than only capping an accumulator, so zero means the memory side of that routing is never
		// taken
		workDir := t.TempDir()
		limiter := NewLimiter(Limits{MaxMemoryBytes: 0, MaxDiskBytes: 10_000})
		charge := limiter.Charge()

		held, err := holdContent(bytes.NewReader(body), workDir, "app.zip", charge, nil)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, held.Close()) })

		assert.Equal(t, []string{"app.zip"}, filesIn(t, workDir), "a zero memory limit holds nothing in memory")
		mem, disk := charge.Held()
		assert.Zero(t, mem)
		assert.Equal(t, int64(500), disk, "and the disk limit still applies to what it overflowed")
	})

	t.Run("a negative memory limit holds content regardless of how much is already held", func(t *testing.T) {
		workDir := t.TempDir()
		limiter := NewLimiter(Limits{MaxMemoryBytes: -1, MaxDiskBytes: 10_000})
		charge := limiter.Charge()
		require.True(t, charge.Memory(1_000_000), "a negative memory limit admits any amount already")

		held, err := holdContent(bytes.NewReader(body), workDir, "app.zip", charge, nil)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, held.Close()) })

		assert.Empty(t, filesIn(t, workDir), "nothing overflows for want of memory when the limit is negative")
		mem, disk := charge.Held()
		assert.Equal(t, int64(1_000_000+len(body)), mem)
		assert.Zero(t, disk)
	})

	t.Run("a zero disk limit writes nothing to disk while content the memory limit admits is still cataloged", func(t *testing.T) {
		workDir := t.TempDir()
		limiter := NewLimiter(Limits{MaxMemoryBytes: 10_000, MaxDiskBytes: 0})
		charge := limiter.Charge()

		held, err := holdContent(bytes.NewReader(body), workDir, "app.zip", charge, nil)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, held.Close()) })

		assert.Empty(t, filesIn(t, workDir), "content the memory limit admits never touches disk")
		mem, disk := charge.Held()
		assert.Equal(t, int64(len(body)), mem)
		assert.Zero(t, disk)
	})

	t.Run("a negative disk limit overflows with no ceiling", func(t *testing.T) {
		workDir := t.TempDir()
		limiter := NewLimiter(Limits{MaxMemoryBytes: 0, MaxDiskBytes: -1})
		charge := limiter.Charge()

		held, err := holdContent(bytes.NewReader(body), workDir, "app.zip", charge, nil)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, held.Close()) })

		assert.Equal(t, []string{"app.zip"}, filesIn(t, workDir))
		assert.Equal(t, body, readAll(t, held))
	})
}

func TestHoldContent_noLimitsAtAll(t *testing.T) {
	// a nil charge is what an extraction with no configured bounds gets, and it must route content
	// rather than panic - holding everything in memory, since nothing is there to refuse it
	workDir := t.TempDir()
	body := []byte("small enough")

	held, err := holdContent(bytes.NewReader(body), workDir, "app.zip", nil, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, held.Close()) })

	assert.Equal(t, body, readAll(t, held))
	assert.Empty(t, filesIn(t, workDir))
}

func TestOpenFileContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.zip")
	require.NoError(t, os.WriteFile(path, []byte("body"), 0o600))

	content, err := OpenFileContent(path)
	require.NoError(t, err)
	assert.Equal(t, "app.zip", content.Name)
	assert.Equal(t, []byte("body"), readAll(t, content))
	require.NoError(t, content.Close())

	_, err = OpenFileContent(filepath.Join(dir, "missing.zip"))
	assert.Error(t, err)
}
