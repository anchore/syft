package archive

import (
	"errors"
	"sync"
)

// Budget bounds the bytes decompressed under one top-level archive, summed over every archive nested in
// it. Unlike Limits it never refills as archives are released: it bounds work, not what is held at once,
// which is what stops a recursive bomb (42.zip) whose every level fits the limits on its own. A nil
// *Budget admits everything.
//
// ponytail: no lock, since the archive walk is sequential; guard it if the walk ever runs concurrently.
type Budget struct {
	remaining int64
}

func NewBudget(bytes int64) *Budget {
	return &Budget{remaining: bytes}
}

// take spends n bytes, or reports false (and spends the rest) when fewer than n remain.
func (b *Budget) take(n int64) bool {
	if b == nil {
		return true
	}
	if n > b.remaining {
		b.remaining = 0
		return false
	}
	b.remaining -= n
	return true
}

var errBudgetSpent = errors.New("archive tree decompression budget spent")

// ErrDiskLimitReached reports that placing an archive's content would exceed the disk limit.
var ErrDiskLimitReached = errors.New("archive content would exceed the disk limit")

// Limits bound how much archive content one scan holds at once. Each limit falls as archives are
// released, so it bounds peak usage rather than the total ever written.
//
// For both limits: positive is the bound, zero forbids the resource, negative is unbounded.
type Limits struct {
	// MaxMemoryBytes bounds archive content held in memory. Content that does not fit is written to
	// disk instead.
	MaxMemoryBytes int64

	// MaxDiskBytes bounds archive content written to disk. Content that does not fit is dropped and
	// the archive is skipped or truncated.
	MaxDiskBytes int64
}

// Limiter tracks how much archive content a scan holds right now against its Limits. A nil *Limiter
// enforces nothing.
type Limiter struct {
	limits Limits

	mu     sync.Mutex
	memory int64
	disk   int64

	peakMemory int64
	peakDisk   int64
}

func NewLimiter(limits Limits) *Limiter {
	return &Limiter{limits: limits}
}

// Peak reports the most memory and disk held at any one moment.
func (l *Limiter) Peak() (memory, disk int64) {
	if l == nil {
		return 0, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.peakMemory, l.peakDisk
}

// InUse reports the memory and disk held right now.
func (l *Limiter) InUse() (memory, disk int64) {
	if l == nil {
		return 0, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.memory, l.disk
}

// charge starts accounting for one archive. Releasing the charge gives back everything it took.
func (l *Limiter) charge() *charge {
	if l == nil {
		return nil
	}
	return &charge{limiter: l}
}

// charge is one archive's draw on a Limiter. A nil *charge admits everything.
//
// Bytes are charged as they land, never from the sizes an archive declares, since those can lie.
type charge struct {
	limiter  *Limiter
	inMemory int64
	onDisk   int64
}

func admits(limit, held, n int64) bool {
	switch {
	case limit < 0:
		return true
	case limit == 0:
		return false
	default:
		return held+n <= limit
	}
}

// memory charges n bytes held in memory, or reports false (charging nothing) when the memory limit
// does not admit them.
func (c *charge) memory(n int64) bool {
	if c == nil || n <= 0 {
		return true
	}
	l := c.limiter
	l.mu.Lock()
	defer l.mu.Unlock()
	if !admits(l.limits.MaxMemoryBytes, l.memory, n) {
		return false
	}
	l.memory += n
	c.inMemory += n
	l.peakMemory = max(l.peakMemory, l.memory)
	return true
}

// disk charges n bytes written to disk, or reports false (charging nothing) when the disk limit does
// not admit them.
func (c *charge) disk(n int64) bool {
	if c == nil || n <= 0 {
		return true
	}
	l := c.limiter
	l.mu.Lock()
	defer l.mu.Unlock()
	if !admits(l.limits.MaxDiskBytes, l.disk, n) {
		return false
	}
	l.disk += n
	c.onDisk += n
	l.peakDisk = max(l.peakDisk, l.disk)
	return true
}

// index charges n bytes of index bookkeeping, which lives in memory whatever the limits say. A zero
// memory limit is a valid configuration that must still index archives, so only then does the cost
// fall back to the disk budget; a bounded memory limit bounds the index too.
func (c *charge) index(n int64) bool {
	if c.memory(n) {
		return true
	}
	return c != nil && c.limiter.limits.MaxMemoryBytes == 0 && c.disk(n)
}

// refundMemory gives back n bytes no longer held in memory.
func (c *charge) refundMemory(n int64) {
	if c == nil || n <= 0 {
		return
	}
	l := c.limiter
	l.mu.Lock()
	defer l.mu.Unlock()
	n = min(n, c.inMemory)
	l.memory -= n
	c.inMemory -= n
}

// refundDisk gives back n bytes no longer on disk.
func (c *charge) refundDisk(n int64) {
	if c == nil || n <= 0 {
		return
	}
	l := c.limiter
	l.mu.Lock()
	defer l.mu.Unlock()
	n = min(n, c.onDisk)
	l.disk -= n
	c.onDisk -= n
}

// release gives back everything this charge took. Safe to call more than once.
func (c *charge) release() {
	if c == nil {
		return
	}
	l := c.limiter
	l.mu.Lock()
	defer l.mu.Unlock()
	l.memory -= c.inMemory
	l.disk -= c.onDisk
	c.inMemory, c.onDisk = 0, 0
}
