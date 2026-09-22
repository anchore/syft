package archive

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLimiter_chargeAndRelease(t *testing.T) {
	limiter := NewLimiter(Limits{MaxMemoryBytes: 100, MaxDiskBytes: 200})

	first := limiter.Charge()
	require.True(t, first.Memory(60))
	require.True(t, first.Disk(150))

	mem, disk := limiter.InUse()
	assert.Equal(t, int64(60), mem)
	assert.Equal(t, int64(150), disk)

	second := limiter.Charge()
	assert.False(t, second.Memory(50), "60 + 50 is over the memory limit")
	assert.False(t, second.Disk(60), "150 + 60 is over the disk limit")
	assert.True(t, second.Memory(40), "and exactly at the limit is admitted")

	mem, _ = limiter.InUse()
	assert.Equal(t, int64(100), mem, "a refused charge takes nothing")

	first.Release()
	mem, disk = limiter.InUse()
	assert.Equal(t, int64(40), mem, "release gives back exactly what that charge took")
	assert.Zero(t, disk)

	first.Release()
	mem, _ = limiter.InUse()
	assert.Equal(t, int64(40), mem, "releasing twice must not give back what was never taken")
}

func TestLimiter_refund(t *testing.T) {
	limiter := NewLimiter(Limits{MaxDiskBytes: 100})
	charge := limiter.Charge()

	require.True(t, charge.Disk(80))
	charge.RefundDisk(80)

	_, disk := limiter.InUse()
	assert.Zero(t, disk)
	assert.True(t, charge.Disk(100), "the refunded room is available again")

	charge.RefundDisk(500)
	_, disk = limiter.InUse()
	assert.Zero(t, disk, "a refund larger than what was charged cannot drive the limiter negative")
}

func TestLimiter_boundsAreIndependent(t *testing.T) {
	memoryBounded := NewLimiter(Limits{MaxMemoryBytes: 10, MaxDiskBytes: -1}).Charge()
	assert.False(t, memoryBounded.Memory(50))
	assert.True(t, memoryBounded.Disk(1_000_000), "a negative disk limit admits anything")

	diskBounded := NewLimiter(Limits{MaxMemoryBytes: 0, MaxDiskBytes: 10}).Charge()
	assert.False(t, diskBounded.Memory(1_000_000), "a zero memory limit refuses everything rather than admitting anything")
	assert.False(t, diskBounded.Disk(50))
}

func TestLimiter_threeStateReadingIsUniform(t *testing.T) {
	t.Run("positive is the limit", func(t *testing.T) {
		c := NewLimiter(Limits{MaxMemoryBytes: 100, MaxDiskBytes: 100}).Charge()
		assert.True(t, c.Memory(100))
		assert.False(t, c.Memory(1))
		assert.True(t, c.Disk(100))
		assert.False(t, c.Disk(1))
	})

	t.Run("zero refuses unconditionally on both", func(t *testing.T) {
		c := NewLimiter(Limits{MaxMemoryBytes: 0, MaxDiskBytes: 0}).Charge()
		assert.False(t, c.Memory(1))
		assert.False(t, c.Disk(1))
	})

	t.Run("negative admits unconditionally on both", func(t *testing.T) {
		c := NewLimiter(Limits{MaxMemoryBytes: -1, MaxDiskBytes: -1}).Charge()
		assert.True(t, c.Memory(1_000_000_000))
		assert.True(t, c.Disk(1_000_000_000))
	})
}

func TestLimiter_nilIsUnbounded(t *testing.T) {
	var limiter *Limiter
	charge := limiter.Charge()
	assert.Nil(t, charge)

	assert.True(t, charge.Memory(1_000_000))
	assert.True(t, charge.Disk(1_000_000))
	charge.RefundDisk(10)
	charge.Release()

	mem, disk := charge.held()
	assert.Zero(t, mem)
	assert.Zero(t, disk)

	mem, disk = limiter.InUse()
	assert.Zero(t, mem)
	assert.Zero(t, disk)
}

func TestLimiter_concurrentChargesAgree(t *testing.T) {
	limiter := NewLimiter(Limits{MaxMemoryBytes: 1_000_000, MaxDiskBytes: -1})

	var wg sync.WaitGroup
	charges := make([]*Charge, 50)
	for i := range charges {
		charges[i] = limiter.Charge()
		wg.Add(1)
		go func(c *Charge) {
			defer wg.Done()
			for range 100 {
				c.Memory(1)
				c.Disk(2)
			}
		}(charges[i])
	}
	wg.Wait()

	mem, disk := limiter.InUse()
	assert.Equal(t, int64(50*100), mem)
	assert.Equal(t, int64(50*100*2), disk)

	for _, c := range charges {
		c.Release()
	}
	mem, disk = limiter.InUse()
	assert.Zero(t, mem)
	assert.Zero(t, disk)
}

func Test_Limiter_peakIsAHighWaterMark(t *testing.T) {
	l := NewLimiter(Limits{MaxMemoryBytes: -1, MaxDiskBytes: -1})

	first := l.Charge()
	require.True(t, first.Memory(100))
	require.True(t, first.Disk(300))
	first.Release()

	second := l.Charge()
	require.True(t, second.Memory(40))
	require.True(t, second.Disk(50))

	memory, disk := l.InUse()
	assert.Equal(t, int64(40), memory)
	assert.Equal(t, int64(50), disk)

	peakMemory, peakDisk := l.Peak()
	assert.Equal(t, int64(100), peakMemory, "the peak is the most held at once, not the most recently held")
	assert.Equal(t, int64(300), peakDisk)
}

func Test_Limiter_peakCountsConcurrentHoldersTogether(t *testing.T) {
	l := NewLimiter(Limits{MaxMemoryBytes: -1, MaxDiskBytes: -1})

	outer := l.Charge()
	require.True(t, outer.Memory(100))
	inner := l.Charge()
	require.True(t, inner.Memory(60))
	inner.Release()
	outer.Release()

	peakMemory, _ := l.Peak()
	assert.Equal(t, int64(160), peakMemory)
}

func Test_Limiter_peakOfANilLimiterIsZero(t *testing.T) {
	var l *Limiter
	memory, disk := l.Peak()
	assert.Zero(t, memory)
	assert.Zero(t, disk)
}

func Test_Limiter_refusedChargeDoesNotMoveThePeak(t *testing.T) {
	l := NewLimiter(Limits{MaxMemoryBytes: 50, MaxDiskBytes: 50})

	c := l.Charge()
	assert.False(t, c.Memory(500))
	assert.False(t, c.Disk(500))

	peakMemory, peakDisk := l.Peak()
	assert.Zero(t, peakMemory)
	assert.Zero(t, peakDisk)
}

func TestCharge_indexFallsBackToDisk(t *testing.T) {
	memoryOnly := NewLimiter(Limits{MaxMemoryBytes: 100, MaxDiskBytes: 0}).Charge()
	assert.True(t, memoryOnly.Index(100))
	assert.False(t, memoryOnly.Index(1), "neither budget admits it")

	diskOnly := NewLimiter(Limits{MaxMemoryBytes: 0, MaxDiskBytes: 100}).Charge()
	assert.True(t, diskOnly.Index(100))
	mem, disk := diskOnly.held()
	assert.Zero(t, mem)
	assert.Equal(t, int64(100), disk)
}
