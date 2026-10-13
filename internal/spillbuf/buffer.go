// Package spillbuf provides a sparse, offset-addressed byte buffer that keeps a bounded amount in memory
// and spills the rest to a temp file.
//
// It exists for the shape where output arrives out of order, at offsets the input itself declares: a
// decompressor placing extents, an archive rebuilding a file from chunks. A plain []byte cannot do that
// without either pre-sizing to a length the input claims or growing to the furthest offset it names, and
// both hand a hostile input an allocation knob.
//
// The buffer reports only what it actually stored. Size is the contiguous run written from offset zero,
// and a read past it is io.EOF rather than the zeros an unwritten region would otherwise hand back. That
// distinction is the whole point: sparse storage serves holes as zeros for free, so a reader that reported
// a length covering them would let a write offset stand in for real output. Anything sizing an allocation
// against this reader (debug/elf's saferio does exactly that) would then allocate bytes nothing produced.
//
// Allocation is bounded by the memory limit rather than by how much is written: filling 1MB and filling
// 64MB cost about the same, because everything past the limit goes to the file. Only memory is bounded
// here: how much ends up on disk is whatever the caller writes, so bounding that stays the caller's job.
package spillbuf

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"slices"

	"github.com/anchore/syft/internal/tmpdir"
)

// DefaultMemLimit is how much a buffer keeps in memory before it spills, when the caller does not say.
// Small on purpose: the memory tier saves a temp file for the common small case, it is not a place to
// hold output. A limit large enough to matter is a limit large enough to be an amplification path.
const DefaultMemLimit int64 = 1 << 20 // 1MB

// ErrNoTempDir is returned when a buffer needs to spill and has nowhere to spill to.
var ErrNoTempDir = errors.New("no temp dir available to spill to")

// Buffer is a sparse, offset-addressed buffer. The zero value is not usable; call New.
//
// Storage is two tiers with a fixed boundary: bytes below memLimit live in mem, bytes at or past it live
// in file. Nothing ever moves between them, so an offset belongs to exactly one tier for the life of the
// buffer and the only case needing care is a range that straddles the boundary.
//
// Not safe for concurrent use. Every consumer writes from a single goroutine, and guarding it would cost
// each write an uncontended lock for no reader.
type Buffer struct {
	td       *tmpdir.TempDir
	memLimit int64

	// mem holds [0, memLimit). Grown geometrically to fit what has been written, never past the limit.
	mem []byte

	// file holds [memLimit, ...), created on the first write that reaches there, so a buffer that stays
	// small never touches disk. remove deletes it on Close.
	file   *os.File
	remove func()

	// written is the set of ranges stored, sorted by start and merged, so runs of adjacent writes collapse
	// to one entry rather than growing per call. Everything the buffer reports comes from it.
	written []extent

	closed bool
}

// extent is a half-open byte range that has been written.
//
// Unexported on purpose. What a caller needs to know about the contents is answered by Size and FirstGap;
// handing out the bookkeeping invites re-deriving those at the call site and getting them subtly wrong,
// which is the bug this package exists to prevent.
type extent struct {
	start, end int64
}

// Option configures a Buffer.
type Option func(*Buffer)

// WithMemLimit sets how many bytes are held in memory before the buffer spills to disk. Zero sends every
// write to the temp file. Negative is treated as zero.
//
// Peak allocation is a small multiple of this, since growing the tier holds the old copy alongside the
// new one and the new one may be rounded up past what was asked for.
func WithMemLimit(n int64) Option {
	return func(b *Buffer) {
		b.memLimit = max(n, 0)
	}
}

// New returns a buffer that spills into td.
//
// td may be nil only when every write is known to stay inside the memory limit; a write past it then
// fails with ErrNoTempDir rather than allocating. Nothing is created on disk until a write needs it.
func New(td *tmpdir.TempDir, opts ...Option) *Buffer {
	b := &Buffer{td: td, memLimit: DefaultMemLimit}
	for _, opt := range opts {
		opt(b)
	}
	return b
}

// split divides a range of n bytes starting at off across the two tiers, reporting how many bytes fall in
// each. The file portion starts at off+inMem.
func (b *Buffer) split(off, n int64) (inMem, inFile int64) {
	if off >= b.memLimit {
		return 0, n
	}
	inMem = min(n, b.memLimit-off)
	return inMem, n - inMem
}

// fileOffset translates a buffer offset at or past the limit into an offset within the spill file.
func (b *Buffer) fileOffset(off int64) int64 { return off - b.memLimit }

// WriteAt stores p at off. Writes may land anywhere, in any order, and may overlap. A write that fails
// leaves the buffer as it was.
func (b *Buffer) WriteAt(p []byte, off int64) (int, error) {
	if b.closed {
		return 0, fmt.Errorf("spillbuf: write to a closed buffer: %w", os.ErrClosed)
	}
	if off < 0 {
		return 0, fmt.Errorf("spillbuf: negative offset %d", off)
	}
	if len(p) == 0 {
		return 0, nil
	}
	// subtraction form so off+len(p) cannot wrap into a small in-range end
	if off > math.MaxInt64-int64(len(p)) {
		return 0, fmt.Errorf("spillbuf: write of %d bytes at %d overflows", len(p), off)
	}

	inMem, inFile := b.split(off, int64(len(p)))
	// the fallible half goes first: once the memory tier is stamped the old bytes are gone, so a file
	// write that fails afterward would report failure over a buffer it had already changed
	if inFile > 0 {
		if err := b.writeFile(p[inMem:], b.fileOffset(off+inMem)); err != nil {
			return 0, err
		}
	}
	if inMem > 0 {
		b.writeMem(p[:inMem], off)
	}

	b.record(extent{start: off, end: off + int64(len(p))})
	return len(p), nil
}

func (b *Buffer) writeMem(p []byte, off int64) {
	if need := off + int64(len(p)); int64(len(b.mem)) < need {
		// geometric, capped at the limit. Sizing to exactly what each write needs looks tidier and is
		// quadratic: a caller streaming a block in 32KB chunks reallocates and copies the whole tier every
		// chunk, so filling 1MB costs ~16MB of allocation.
		grown := min(b.memLimit, max(need, 2*int64(len(b.mem))))
		// sized to exactly the geometric target rather than grown through append: append rounds the new
		// capacity up past what was asked for, and the tier is already capped, so the slack is pure waste
		mem := make([]byte, grown)
		copy(mem, b.mem)
		b.mem = mem
	}
	copy(b.mem[off:], p)
}

func (b *Buffer) writeFile(p []byte, off int64) error {
	if b.file == nil {
		if b.td == nil {
			return ErrNoTempDir
		}
		f, remove, err := b.td.NewFile("syft-spill-*.bin") //nolint:gocritic // removal happens in Close
		if err != nil {
			return fmt.Errorf("spillbuf: unable to create spill file: %w", err)
		}
		b.file, b.remove = f, remove
	}
	if _, err := b.file.WriteAt(p, off); err != nil {
		return fmt.Errorf("spillbuf: unable to write to spill file: %w", err)
	}
	return nil
}

// ReadAt returns bytes this buffer actually stored. A read starting at or past Size is io.EOF, and one
// running past it is short, because everything beyond is a hole the buffer never held.
func (b *Buffer) ReadAt(p []byte, off int64) (int, error) {
	if b.closed {
		return 0, fmt.Errorf("spillbuf: read from a closed buffer: %w", os.ErrClosed)
	}
	if off < 0 {
		return 0, fmt.Errorf("spillbuf: negative offset %d", off)
	}
	if len(p) == 0 {
		return 0, nil
	}
	size := b.Size()
	if off >= size {
		return 0, io.EOF
	}

	// bounded by Size, so every byte in [off, off+want) was written and both tiers really hold theirs
	want := min(int64(len(p)), size-off)
	inMem, inFile := b.split(off, want)

	// guarded rather than relying on a zero-length copy: when off is past the limit the slice expression
	// itself is out of range, since mem is only as long as what was written into it
	if inMem > 0 {
		copy(p[:inMem], b.mem[off:off+inMem])
	}
	if inFile > 0 {
		if err := readFullAt(b.file, p[inMem:want], b.fileOffset(off+inMem)); err != nil {
			return int(inMem), fmt.Errorf("spillbuf: unable to read spill file: %w", err)
		}
	}

	if want < int64(len(p)) {
		return int(want), io.EOF
	}
	return int(want), nil
}

// readFullAt fills p from r. A short read is an error rather than a short return: the caller has already
// bounded the range by what was written, so the file failing to deliver means it is not what we left.
func readFullAt(r io.ReaderAt, p []byte, off int64) error {
	for read := 0; read < len(p); {
		n, err := r.ReadAt(p[read:], off+int64(read))
		read += n
		if err != nil {
			return err
		}
	}
	return nil
}

// Size reports the contiguous run written from offset zero, which is the length this buffer is willing to
// stand behind. Deliberately not the furthest offset written: see the package doc for why the two are not
// interchangeable.
//
// record keeps the set merged and sorted, so the run from zero is at most the first two entries and the
// loop stops there: the cost this adds to every ReadAt is effectively constant, not a scan of the set.
func (b *Buffer) Size() int64 {
	var covered int64
	for _, e := range b.written {
		if e.start > covered {
			break
		}
		covered = max(covered, e.end)
	}
	return covered
}

// FirstGap returns the offset of the earliest unwritten run of at least size bytes lying entirely within
// [0, within), and whether there is one. Callers that place output at offsets of their own choosing use it
// to fill what they left behind, without needing the buffer's bookkeeping.
//
// The arithmetic is in subtraction form throughout: within comes from caller input and the result is used
// as a write offset, so a wrap here would be a write nobody bounded.
func (b *Buffer) FirstGap(size, within int64) (int64, bool) {
	if b.closed || size < 0 || within < 0 {
		return 0, false
	}

	var at int64
	for _, e := range b.written {
		// once the cursor is at the bound there is nothing left to offer, and it only moves forward
		if at >= within {
			return 0, false
		}
		// the gap ahead of this extent ends at whichever comes first, the extent or the bound
		end := min(e.start, within)
		if end > at && end-at >= size {
			return at, true
		}
		at = max(at, e.end)
	}
	if at <= within && within-at >= size {
		return at, true
	}
	return 0, false
}

// record merges e into the written set, keeping it sorted by start with no overlapping or adjacent pairs.
func (b *Buffer) record(e extent) {
	if e.end <= e.start {
		return
	}

	// inserted in place rather than appended and re-sorted: the set is already ordered, so a run of
	// ascending writes (the common case) stays linear
	i, _ := slices.BinarySearchFunc(b.written, e, func(x, y extent) int {
		return cmpInt64(x.start, y.start)
	})
	b.written = slices.Insert(b.written, i, e)

	merged := b.written[:1]
	for _, cur := range b.written[1:] {
		last := &merged[len(merged)-1]
		if cur.start <= last.end {
			last.end = max(last.end, cur.end)
			continue
		}
		merged = append(merged, cur)
	}
	b.written = merged
}

func cmpInt64(x, y int64) int {
	switch {
	case x < y:
		return -1
	case x > y:
		return 1
	}
	return 0
}

// Close releases the spill file, if one was ever created, and drops the memory tier. Safe on a nil
// receiver and safe to call more than once. Reads and writes after it fail with os.ErrClosed.
func (b *Buffer) Close() error {
	if b == nil {
		return nil
	}
	b.mem = nil
	b.written = nil
	b.closed = true
	if b.file == nil {
		return nil
	}
	err := b.file.Close()
	if b.remove != nil {
		b.remove()
	}
	b.file, b.remove = nil, nil
	return err
}
