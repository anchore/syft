package archive

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLimiter_chargeAndRelease(t *testing.T) {
	limiter := NewLimiter(Limits{MaxMemoryBytes: 100, MaxDiskBytes: 200})

	first := limiter.charge()
	require.True(t, first.memory(60))
	require.True(t, first.disk(150))

	mem, disk := limiter.InUse()
	assert.Equal(t, int64(60), mem)
	assert.Equal(t, int64(150), disk)

	second := limiter.charge()
	assert.False(t, second.memory(50), "60 + 50 is over the memory limit")
	assert.False(t, second.disk(60), "150 + 60 is over the disk limit")
	assert.True(t, second.memory(40), "and exactly at the limit is admitted")

	mem, _ = limiter.InUse()
	assert.Equal(t, int64(100), mem, "a refused charge takes nothing")

	first.release()
	mem, disk = limiter.InUse()
	assert.Equal(t, int64(40), mem, "release gives back exactly what that charge took")
	assert.Zero(t, disk)

	first.release()
	mem, _ = limiter.InUse()
	assert.Equal(t, int64(40), mem, "releasing twice must not give back what was never taken")
}

func TestLimiter_refund(t *testing.T) {
	limiter := NewLimiter(Limits{MaxDiskBytes: 100})
	charge := limiter.charge()

	require.True(t, charge.disk(80))
	charge.refundDisk(80)

	_, disk := limiter.InUse()
	assert.Zero(t, disk)
	assert.True(t, charge.disk(100), "the refunded room is available again")

	charge.refundDisk(500)
	_, disk = limiter.InUse()
	assert.Zero(t, disk, "a refund larger than what was charged cannot drive the limiter negative")
}

func TestLimiter_threeStateReadingIsUniform(t *testing.T) {
	t.Run("positive is the limit", func(t *testing.T) {
		c := NewLimiter(Limits{MaxMemoryBytes: 100, MaxDiskBytes: 100}).charge()
		assert.True(t, c.memory(100))
		assert.False(t, c.memory(1))
		assert.True(t, c.disk(100))
		assert.False(t, c.disk(1))
	})

	t.Run("zero refuses unconditionally on both", func(t *testing.T) {
		c := NewLimiter(Limits{MaxMemoryBytes: 0, MaxDiskBytes: 0}).charge()
		assert.False(t, c.memory(1))
		assert.False(t, c.disk(1))
	})

	t.Run("negative admits unconditionally on both", func(t *testing.T) {
		c := NewLimiter(Limits{MaxMemoryBytes: -1, MaxDiskBytes: -1}).charge()
		assert.True(t, c.memory(1_000_000_000))
		assert.True(t, c.disk(1_000_000_000))
	})
}

func TestLimiter_nilIsUnbounded(t *testing.T) {
	var limiter *Limiter
	charge := limiter.charge()
	assert.Nil(t, charge)

	assert.True(t, charge.memory(1_000_000))
	assert.True(t, charge.disk(1_000_000))
	charge.refundDisk(10)
	charge.release()

	mem, disk := charge.held()
	assert.Zero(t, mem)
	assert.Zero(t, disk)

	mem, disk = limiter.InUse()
	assert.Zero(t, mem)
	assert.Zero(t, disk)

	mem, disk = limiter.Peak()
	assert.Zero(t, mem)
	assert.Zero(t, disk)
}

func TestLimiter_concurrentChargesAgree(t *testing.T) {
	limiter := NewLimiter(Limits{MaxMemoryBytes: 1_000_000, MaxDiskBytes: -1})

	var wg sync.WaitGroup
	charges := make([]*charge, 50)
	for i := range charges {
		charges[i] = limiter.charge()
		wg.Add(1)
		go func(c *charge) {
			defer wg.Done()
			for range 100 {
				c.memory(1)
				c.disk(2)
			}
		}(charges[i])
	}
	wg.Wait()

	mem, disk := limiter.InUse()
	assert.Equal(t, int64(50*100), mem)
	assert.Equal(t, int64(50*100*2), disk)

	for _, c := range charges {
		c.release()
	}
	mem, disk = limiter.InUse()
	assert.Zero(t, mem)
	assert.Zero(t, disk)
}

func TestLimiter_peak(t *testing.T) {
	t.Run("is a high-water mark", func(t *testing.T) {
		l := NewLimiter(Limits{MaxMemoryBytes: -1, MaxDiskBytes: -1})

		first := l.charge()
		require.True(t, first.memory(100))
		require.True(t, first.disk(300))
		first.release()

		second := l.charge()
		require.True(t, second.memory(40))
		require.True(t, second.disk(50))

		memory, disk := l.InUse()
		assert.Equal(t, int64(40), memory)
		assert.Equal(t, int64(50), disk)

		peakMemory, peakDisk := l.Peak()
		assert.Equal(t, int64(100), peakMemory, "the peak is the most held at once, not the most recently held")
		assert.Equal(t, int64(300), peakDisk)
	})

	t.Run("counts concurrent holders together", func(t *testing.T) {
		l := NewLimiter(Limits{MaxMemoryBytes: -1, MaxDiskBytes: -1})

		outer := l.charge()
		require.True(t, outer.memory(100))
		inner := l.charge()
		require.True(t, inner.memory(60))
		inner.release()
		outer.release()

		peakMemory, _ := l.Peak()
		assert.Equal(t, int64(160), peakMemory)
	})

	t.Run("a refused charge does not move it", func(t *testing.T) {
		l := NewLimiter(Limits{MaxMemoryBytes: 50, MaxDiskBytes: 50})

		c := l.charge()
		assert.False(t, c.memory(500))
		assert.False(t, c.disk(500))

		peakMemory, peakDisk := l.Peak()
		assert.Zero(t, peakMemory)
		assert.Zero(t, peakDisk)
	})
}
