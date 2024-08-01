package xfs

import "fmt"

var (
	_ Cache[string, Inode] = &mockCache[string, Inode]{}
)

type Cache[K comparable, V any] interface {
	// Add cache data
	Add(key K, value V) bool

	// Get returns key's value from the cache
	Get(key K) (value V, ok bool)
}

type mockCache[K string, V any] struct{}

func (c *mockCache[K, V]) Add(_ K, _ V) bool {
	return false
}

func (c *mockCache[K, V]) Get(_ K) (v V, evicted bool) {
	return
}

func inodeCacheKey(n uint64) string {
	return fmt.Sprintf("xfs:%d", n)
}
