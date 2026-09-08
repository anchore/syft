package javascript

import (
	"context"
	"sync"

	"github.com/anchore/syft/syft/pkg/cataloger/internal/licenses"
)

// defaultNpmPrefetchConcurrency bounds how many npm registry requests run in
// parallel while warming the cache for one lockfile. Kept modest so scanning a
// large lockfile does not open an unbounded number of connections or trip
// registry rate limits.
const defaultNpmPrefetchConcurrency = 8

type licenseCacheKey struct{}

type licenseCache struct {
	mu sync.Mutex
	m  map[string]string
}

func (c *licenseCache) set(k, v string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[k] = v
}

func (c *licenseCache) get(k string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.m[k]
	return v, ok
}

// withLicenseCache stores a per-parse in-memory license cache in ctx.
func withLicenseCache(ctx context.Context) context.Context {
	return context.WithValue(ctx, licenseCacheKey{}, &licenseCache{m: make(map[string]string)})
}

func cacheSet(ctx context.Context, name, version, license string) {
	if c, ok := ctx.Value(licenseCacheKey{}).(*licenseCache); ok && license != "" {
		c.set(name+"@"+version, license)
	}
}

func cacheGet(ctx context.Context, name, version string) (string, bool) {
	if c, ok := ctx.Value(licenseCacheKey{}).(*licenseCache); ok {
		return c.get(name + "@" + version)
	}
	return "", false
}

// prefetchNpmLicenses issues bounded-concurrency registry lookups for every
// (name, version) pair and writes each result into the ctx cache, so the
// per-package constructors resolve their lookup locally instead of performing
// N strictly sequential HTTP round-trips
// (see https://github.com/anchore/syft/issues/5193).
//
// A failed or missing entry is simply not cached: the constructor falls back to
// its original inline request path, preserving existing behavior (including
// error logging) for anything the prefetch could not fetch.
func prefetchNpmLicenses(ctx context.Context, cfg CatalogerConfig, pairs [][2]string) {
	if len(pairs) == 0 || !cfg.SearchRemoteLicenses {
		return
	}

	keys := make([]string, 0, len(pairs))
	for _, p := range pairs {
		keys = append(keys, pairKey(p[0], p[1]))
	}

	licenses.Prefetch(ctx, keys, defaultNpmPrefetchConcurrency, func(ctx context.Context, key string) error {
		name, version := unpairKey(key)
		license, err := getLicenseFromNpmRegistry(cfg.NPMBaseURL, name, version)
		if err != nil {
			return err
		}
		cacheSet(ctx, name, version, license)
		return nil
	})
}

func pairKey(name, version string) string { return name + "@" + version }

// unpairKey splits "name@version" on the last '@' that is not part of a
// scoped package name (e.g. "@babel/code-frame@7.10.4" -> "@babel/code-frame",
// "7.10.4").
func unpairKey(key string) (name, version string) {
	for i := len(key) - 1; i > 0; i-- {
		if key[i] == '@' && key[i-1] != '/' {
			return key[:i], key[i+1:]
		}
	}
	// no separator found: treat everything as the package name with an empty version
	return key, ""
}
