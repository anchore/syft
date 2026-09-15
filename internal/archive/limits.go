package archive

import (
	"errors"
	"sync"
)

// ErrDiskLimitReached reports that an archive's content could not be admitted because placing it
// would have taken disk usage past the disk limit. It is not a failure of the scan: the archive is
// skipped and the walk continues.
var ErrDiskLimitReached = errors.New("archive content would exceed the disk limit")

// Limits bounds how much archive content one scan may hold at once, and decides where an
// archive's content is held.
//
// These are in-use limits rather than counters. An in-use limit measures what is held right now and
// falls when an archive is released, so what it bounds is a scan's peak concurrent usage. A bound on
// bytes ever written measures no state that ever exists, because every archive's extraction directory
// is removed on the way out: it would restrict a long scan of small archives that never held much at
// once, and permit a deep scan that held far more.
//
// Both fields read three states the same way: positive is the limit, zero means none of that
// resource may be used at all, and negative means that resource is not bounded. Unbounded is a real
// hazard on either - a crafted archive can exhaust memory or disk - so it is reachable only by asking
// for it explicitly with a negative value, never as the reading of an unset or zeroed field.
type Limits struct {
	// MaxMemoryBytes bounds the archive content held in memory at once. Content is held in memory
	// while this admits it and overflows to disk when it does not - there is no separate configured size
	// at which overflowing begins. Zero holds nothing, sending every archive's content to disk;
	// negative holds content regardless of how much is already held.
	MaxMemoryBytes int64

	// MaxDiskBytes bounds the archive content placed on disk at once: content overflowed there instead
	// of being held in memory, plus the bytes of the entries extracted from it. Zero writes nothing
	// to disk, so content that does not fit in memory has nowhere to go and its archive is skipped;
	// negative overflows as needed with no ceiling.
	MaxDiskBytes int64
}

// Limiter measures how much archive content a scan is holding right now. One instance per task run,
// which is one scan - the only scoping under which "held at once" means anything.
//
// Guarded by a mutex even though the archive walk is sequential today: the archive task merges into
// a shared builder while top-level catalogers run, so this code already lives in a concurrent
// neighbourhood and an unguarded total here would be a data race the day someone parallelises the
// walk.
//
// A nil *Limiter enforces nothing, which is what an extraction with no configured bounds gets.
type Limiter struct {
	limits Limits
	mu     sync.Mutex
	memory int64
	disk   int64

	// peaks are the high-water marks of the two gauges above: the most this scan held at any one
	// moment, rather than the sum of what every archive held. They only ever rise, which is the one
	// place in this type where that is correct - a peak that fell on release would be measuring the
	// same thing the gauge already measures.
	peakMemory int64
	peakDisk   int64
}

// NewLimiter returns a limiter enforcing the given limits.
func NewLimiter(limits Limits) *Limiter {
	return &Limiter{limits: limits}
}

// MaxDiskBytes returns the configured disk bound, for attributing a skip in a log line.
func (l *Limiter) MaxDiskBytes() int64 {
	if l == nil {
		return 0
	}
	return l.limits.MaxDiskBytes
}

// Peak reports the most archive content this scan held at any one moment, in memory and on disk.
// These are the same quantities the limits bound, so they say how close a scan came to them.
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

// Charge starts one archive's accounting against this limiter. Releasing the returned charge gives
// back exactly what it took, which is what makes this a limiter rather than a counter.
func (l *Limiter) Charge() *Charge {
	if l == nil {
		return nil
	}
	return &Charge{limiter: l}
}

// Charge is one archive's accumulated draw on the limiter.
//
// Bytes are charged to it as they land, never from a size an entry declared: both tar and zip
// headers carry an entry size and a crafted archive is free to lie about it, so a reservation made
// against a declared size bounds what an attacker claims rather than what the machine does. The
// charge accumulates what was actually taken, so Release returns exactly that.
//
// A nil *Charge charges nothing and refuses nothing.
type Charge struct {
	limiter *Limiter
	memory  int64
	disk    int64
}

// admitsThreeState reports whether n more bytes may be charged against a limit that is already
// holding held, reading the limit the same way on both bounds it governs: positive is the limit
// itself, zero refuses unconditionally (none of that resource may be used at all), and negative
// admits unconditionally (that resource is not bounded). One reading shared by Memory and Disk
// rather than the same three-way condition written twice, since the two have already drifted once.
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

// Memory charges n bytes of content held in memory, reporting false when the memory limit does not
// admit it - which for a zero limit is every chunk, sending content to disk unconditionally, since
// there is no separate threshold naming a size at which content overflows. Nothing is charged when it
// reports false.
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

// Disk charges n bytes of content placed on disk, reporting false when the disk limit does not admit
// it - which for a zero limit is every chunk, so content with nowhere further to go leaves its
// archive skipped exactly as content exceeding a positive disk limit does. Nothing is charged when it
// reports false.
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

// IndexRecord charges the in-memory cost of holding one entry's index record - the *Entry, its
// header, and the resolver node built over it - preferring the memory budget and overflowing to the
// disk budget when memory will not admit it.
//
// It overflows rather than refusing because the index is not content: a resolver needs an entry's
// record to reach that entry's bytes at all, and the memory budget may legitimately be zero, so an
// index that could be refused would leave an archive whose content is entirely on disk with no way to
// read it back. What this bounds instead is entry count - the one dimension the byte budgets never
// bounded, so an archive of millions of empty entries could grow the index without limit. It reports
// false only when neither budget admits the record, which truncates the archive. What it charges is
// released by Release along with everything else this charge took, so the index accounting falls when
// the archive does.
func (c *Charge) IndexRecord(n int64) bool {
	if c == nil || c.limiter == nil || n <= 0 {
		return true
	}
	if c.Memory(n) {
		return true
	}
	return c.Disk(n)
}

// RefundDisk gives back n bytes charged for content that was removed again, so a partial file
// dropped at a limit does not leave the limiter holding bytes that are no longer on disk.
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

// Held reports what this charge is currently holding, in memory and on disk.
func (c *Charge) Held() (memory, disk int64) {
	if c == nil || c.limiter == nil {
		return 0, 0
	}
	c.limiter.mu.Lock()
	defer c.limiter.mu.Unlock()
	return c.memory, c.disk
}

// Release returns everything this charge took, so both limits fall by what this archive held. Safe
// to call more than once.
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
