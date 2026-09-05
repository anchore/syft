package licenses

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrefetchCallsEveryKey(t *testing.T) {
	var calls atomic.Int64
	Prefetch(context.Background(), []string{"a", "b", "c"}, 2, func(_ context.Context, _ string) error {
		calls.Add(1)
		return nil
	})
	assert.Equal(t, int64(3), calls.Load())
}

func TestPrefetchEmptyKeys(t *testing.T) {
	called := false
	Prefetch(context.Background(), nil, 4, func(_ context.Context, _ string) error {
		called = true
		return nil
	})
	assert.False(t, called, "fn should not run when there are no keys")
}

func TestPrefetchContinuesAfterError(t *testing.T) {
	var calls atomic.Int64
	Prefetch(context.Background(), []string{"bad", "good"}, 1, func(_ context.Context, key string) error {
		calls.Add(1)
		if key == "bad" {
			return errors.New("boom")
		}
		return nil
	})
	assert.Equal(t, int64(2), calls.Load(), "an error on one key must not prevent the remaining lookups")
}

func TestPrefetchRespectsConcurrencyLimit(t *testing.T) {
	release := make(chan struct{})
	var inFlight, maxInFlight atomic.Int64

	done := make(chan struct{})
	go func() {
		defer close(done)
		keys := make([]string, 16)
		for i := range keys {
			keys[i] = "k"
		}
		Prefetch(context.Background(), keys, 3, func(_ context.Context, _ string) error {
			cur := inFlight.Add(1)
			// track the high-water mark of simultaneous workers
			for {
				m := maxInFlight.Load()
				if cur <= m || maxInFlight.CompareAndSwap(m, cur) {
					break
				}
			}
			<-release
			inFlight.Add(-1)
			return nil
		})
	}()

	// give the pool a moment to saturate, then let everything through
	time.Sleep(50 * time.Millisecond)
	close(release)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("prefetch did not finish")
	}

	assert.LessOrEqual(t, maxInFlight.Load(), int64(3), "concurrency limit was exceeded")
	require.Greater(t, maxInFlight.Load(), int64(1), "work should actually overlap")
}
