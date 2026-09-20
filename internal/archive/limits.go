package archive

import (
	"errors"
	"sync"
)

// ErrDiskLimitReached reports that placing an archive's content would exceed the disk limit. Not a
// scan failure: the archive is skipped and the walk continues.
var ErrDiskLimitReached = errors.New("archive content would exceed the disk limit")

// Limits bounds how much archive content one scan may hold at once, and so where content is held.
//
// These are in-use limits, not counters: each measures what is held right now and falls when an
// archive is released, bounding peak concurrent usage. Work directories are removed on release, so a
// bound on bytes ever written would measure state that never exists at once.
//
// Both fields read three states the same way: positive is the limit, zero forbids that resource, and
// negative is unbounded. Unbounded is a real hazard, so it must be asked for explicitly.
type Limits struct {
	// MaxMemoryBytes bounds archive content held in memory at once; content spills to disk when it does
	// not admit more, so there is no separate spill threshold. Zero sends all content to disk; negative
	// is unbounded.
	MaxMemoryBytes int64

	// MaxDiskBytes bounds archive content on disk at once: content spilled there plus the entry bytes
	// extracted from it. Zero writes nothing, so content that does not fit in memory has nowhere to go
	// and its archive is skipped; negative is unbounded.
	MaxDiskBytes int64
}

// Limiter measures how much archive content a scan is holding right now. One instance per task run
// (one scan), the only scope under which "held at once" means anything. A nil *Limiter enforces
// nothing. Mutex-guarded because the archive task merges into a shared builder while top-level
// catalogers run.
type Limiter struct {
	limits Limits
	mu     sync.Mutex
	memory int64
	disk   int64

	// peaks are high-water marks of the two gauges above: the most held at any one moment, not the sum
	// across archives. They only rise.
	peakMemory int64
	peakDisk   int64
}

// NewLimiter returns a limiter enforcing the given limits.
func NewLimiter(limits Limits) *Limiter {
	return &Limiter{limits: limits}
}

// Peak reports the most archive content held at any one moment, the quantities the limits bound.
func (l *Limiter) Peak() (memory, disk int64) {
	if l == nil {
		return 0, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.peakMemory, l.peakDisk
}

// InUse reports the archive content held right now, in memory and on disk.
func (l *Limiter) InUse() (memory, disk int64) {
	if l == nil {
		return 0, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.memory, l.disk
}

// Charge starts one archive's accounting. Releasing the returned charge gives back what it took.
func (l *Limiter) Charge() *Charge {
	if l == nil {
		return nil
	}
	return &Charge{limiter: l}
}

// Charge is one archive's accumulated draw on the limiter. A nil *Charge charges and refuses nothing.
//
// Bytes are charged as they land, never from a declared size: tar and zip headers both carry a size a
// crafted archive can lie about, so reserving against it would bound the claim, not the usage.
type Charge struct {
	limiter *Limiter
	memory  int64
	disk    int64
}

// admitsThreeState reports whether n more bytes may be charged against a limit already holding held.
// Shared by Memory and Disk so the two readings of Limits cannot drift.
func admitsThreeState(limit, held, n int64) bool {
	switch {
	case limit < 0:
		return true
	case limit == 0:
		return false
	default:
		return held+n <= limit
	}
}

// Memory charges n bytes held in memory, reporting false when the memory limit does not admit it (for
// a zero limit, always). Nothing is charged when it reports false.
func (c *Charge) Memory(n int64) bool {
	if c == nil || c.limiter == nil || n <= 0 {
		return true
	}
	l := c.limiter
	l.mu.Lock()
	defer l.mu.Unlock()
	if !admitsThreeState(l.limits.MaxMemoryBytes, l.memory, n) {
		return false
	}
	l.memory += n
	c.memory += n
	if l.memory > l.peakMemory {
		l.peakMemory = l.memory
	}
	return true
}

// Disk charges n bytes placed on disk, reporting false when the disk limit does not admit it (for a
// zero limit, always, which skips the archive). Nothing is charged when it reports false.
func (c *Charge) Disk(n int64) bool {
	if c == nil || c.limiter == nil || n <= 0 {
		return true
	}
	l := c.limiter
	l.mu.Lock()
	defer l.mu.Unlock()
	if !admitsThreeState(l.limits.MaxDiskBytes, l.disk, n) {
		return false
	}
	l.disk += n
	c.disk += n
	if l.disk > l.peakDisk {
		l.peakDisk = l.disk
	}
	return true
}

// IndexRecord charges the memory an archive's index records keep regardless of content weight,
// preferring the memory budget and falling back to disk. It reports false only when neither budget
// admits the record, truncating the archive.
//
// It bounds the dimension the byte budgets miss: an archive of many empty entries, or one entry named
// a thousand components deep, weighs almost nothing as content yet would grow the index without limit.
//
// The disk fallback exists because a resolver needs an entry's record to reach its bytes at all, and
// MaxMemoryBytes may legitimately be zero (the configuration that spills every archive). So records
// are bounded by the disk budget once memory is full, though they are only ever held in memory.
func (c *Charge) IndexRecord(n int64) bool {
	if c == nil || c.limiter == nil || n <= 0 {
		return true
	}
	if c.Memory(n) {
		return true
	}
	return c.Disk(n)
}

// RefundDisk gives back n bytes charged for content since removed, so a partial file dropped at a
// limit does not leave the limiter holding bytes no longer on disk.
func (c *Charge) RefundDisk(n int64) {
	if c == nil || c.limiter == nil || n <= 0 {
		return
	}
	l := c.limiter
	l.mu.Lock()
	defer l.mu.Unlock()
	if n > c.disk {
		n = c.disk
	}
	l.disk -= n
	c.disk -= n
}

// RefundMemory gives back n bytes charged for content no longer held in memory.
func (c *Charge) RefundMemory(n int64) {
	if c == nil || c.limiter == nil || n <= 0 {
		return
	}
	l := c.limiter
	l.mu.Lock()
	defer l.mu.Unlock()
	if n > c.memory {
		n = c.memory
	}
	l.memory -= n
	c.memory -= n
}

// Release returns everything this charge took. Safe to call more than once.
func (c *Charge) Release() {
	if c == nil || c.limiter == nil {
		return
	}
	l := c.limiter
	l.mu.Lock()
	defer l.mu.Unlock()
	l.memory -= c.memory
	l.disk -= c.disk
	c.memory, c.disk = 0, 0
}
