package cachemanager

import (
	"fmt"

	"github.com/anchore/go-cache"
)

// Get returns the global cache manager, which is used to instantiate all caches
func Get() cache.Manager {
	return manager
}

// Set sets the global cache manager, which is used to instantiate all caches.
// Setting this to nil disables caching.
func Set(m cache.Manager) {
	if m == nil {
		manager = cache.NewBypassed()
	} else {
		manager = m
	}
}

func GetResolverCachingErrors[T any](name, version string) cache.Resolver[T] {
	return cache.NewResolverCachingErrors[T](manager.GetCache(name, fmt.Sprintf("%s/%s", version, cache.HashType[T]())))
}

var manager = cache.NewBypassed()
