package licenses

import (
	"context"
	"sync"

	"github.com/anchore/syft/internal/log"
)

// defaultPrefetchConcurrency bounds how many registry requests run in parallel
// during a prefetch pass. The limit exists so a large lockfile cannot open an
// unbounded number of connections or trip registry rate limits.
const defaultPrefetchConcurrency = 8

// Prefetch calls fn for every key in keys using a bounded pool of workers.
//
// It exists because several catalogers perform one remote registry lookup per
// package inside their per-package constructors. When those constructors are
// invoked from the parser's main loop the lookups serialize, which makes SBOM
// generation for large lockfiles slow even though the lookups are independent.
// A cataloger can instead collect its (name, version) pairs and hand them to
// Prefetch before constructing packages; each constructor's own lookup then
// resolves without blocking on the previous package's round-trip.
//
// Results are delivered through fn itself (typically by writing into a cache);
// Prefetch returns once every key has been attempted. Errors from individual
// keys are logged at debug level and do not stop the remaining lookups — the
// per-package constructor re-attempts any missing entry and surfaces its error
// exactly as it did before this helper existed.
func Prefetch(ctx context.Context, keys []string, concurrency int, fn func(ctx context.Context, key string) error) {
	if len(keys) == 0 {
		return
	}
	if concurrency <= 0 {
		concurrency = defaultPrefetchConcurrency
	}

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, key := range keys {
		wg.Add(1)
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			// parent context cancelled: stop issuing new work and let the
			// in-flight attempts observe cancellation themselves
			wg.Done()
			wg.Wait()
			log.WithFields("error", ctx.Err()).Trace("prefetch cancelled before all keys were attempted")
			return
		}
		go func(key string) {
			defer wg.Done()
			defer func() { <-sem }()
			if err := fn(ctx, key); err != nil {
				log.WithFields("key", key, "error", err).Debug("prefetch lookup failed")
			}
		}(key)
	}

	wg.Wait()
}
