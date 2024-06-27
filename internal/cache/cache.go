package cache

import (
	"io"
)

// Manager is responsible for managing cache data and instantiating all caches
type Manager interface {
	// GetCache returns a cache scoped to the given named, versioned data
	GetCache(name, version string) Cache

	// RootDirs returns any root directories this cache manager uses
	RootDirs() []string
}

// ReaderAtCloser is an amalgamation of: io.Reader, io.ReaderAt, and io.Closer
type ReaderAtCloser interface {
	io.Reader
	io.ReaderAt
	io.Closer
}

// Cache is what the application interacts with to get and set cached data
type Cache interface {
	// Read returns a reader for the cache value, if found and not expired
	// or errors when unable to find / expired
	Read(key string) (ReaderAtCloser, error)

	// Write writes the contents of the reader to the cache
	// and closes it, if the reader implements io.Closer
	Write(key string, contents io.Reader) error
}

// GetManager returns the global cache manager, which is used to instantiate all caches
func GetManager() Manager {
	return manager
}

// SetManager sets the global cache manager, which is used to instantiate all caches.
// Setting this to nil disables caching.
func SetManager(m Manager) {
	if m == nil {
		manager = &bypassedCache{}
	} else {
		manager = m
	}
}

var manager Manager = &bypassedCache{}
