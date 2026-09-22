package archive

import (
	"errors"
	"sync"
)

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

// Charge starts accounting for one archive. Releasing the charge gives back everything it took.
func (l *Limiter) Charge() *Charge {
	if l == nil {
		return nil
	}
	return &Charge{limiter: l}
}

// Charge is one archive's draw on a Limiter. A nil *Charge admits everything.
//
// Bytes are charged as they land, never from the sizes an archive declares, since those can lie.
type Charge struct {
	limiter *Limiter
	memory  int64
	disk    int64
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

// Memory charges n bytes held in memory, or reports false (charging nothing) when the memory limit
// does not admit them.
func (c *Charge) Memory(n int64) bool {
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
	c.memory += n
	l.peakMemory = max(l.peakMemory, l.memory)
	return true
}

// Disk charges n bytes written to disk, or reports false (charging nothing) when the disk limit does
// not admit them.
func (c *Charge) Disk(n int64) bool {
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
	c.disk += n
	l.peakDisk = max(l.peakDisk, l.disk)
	return true
}

// Index charges n bytes of index bookkeeping. The index always lives in memory, but a zero memory
// limit is a valid configuration that must still index archives, so it falls back to the disk
// budget when memory does not admit it. Reports false only when neither does.
func (c *Charge) Index(n int64) bool {
	return c.Memory(n) || c.Disk(n)
}

// RefundMemory gives back n bytes no longer held in memory.
func (c *Charge) RefundMemory(n int64) {
	if c == nil || n <= 0 {
		return
	}
	l := c.limiter
	l.mu.Lock()
	defer l.mu.Unlock()
	n = min(n, c.memory)
	l.memory -= n
	c.memory -= n
}

// RefundDisk gives back n bytes no longer on disk.
func (c *Charge) RefundDisk(n int64) {
	if c == nil || n <= 0 {
		return
	}
	l := c.limiter
	l.mu.Lock()
	defer l.mu.Unlock()
	n = min(n, c.disk)
	l.disk -= n
	c.disk -= n
}

// Release gives back everything this charge took. Safe to call more than once.
func (c *Charge) Release() {
	if c == nil {
		return
	}
	l := c.limiter
	l.mu.Lock()
	defer l.mu.Unlock()
	l.memory -= c.memory
	l.disk -= c.disk
	c.memory, c.disk = 0, 0
}
