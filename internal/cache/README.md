# Caching

All caches are created from a global `manager`. By defaut this is a `bypassedCache`, which performs no caching.
One benefit of this is that tests don't need to worry about caching causing issues unless they explicitly need
to test the cache and can opt-in using the `cache.TestCache(t)` helper.

Syft sets a `filesystemCache` when the [cache options](../../cmd/syft/internal/options/cache.go) are loaded.

When using the `filesystemCache` all items are stored on disk under a root directory, generally in the form of:
```
<rootDir>/<named-cache>/<data-version>/path/to/data
```

# Using the cache

The easiest and preferred method to use the cache is a `cache.Resolver`, which automatically creates a `<data-version>`
based on the _structure_ of the provided type.
If the structure changes in any way it will end up with a new version key and all will re populate this new key,
ignoring cached values from older, different versions.
The resolver will store items using the `json` package to serialize/deserialize values, so to save space
it is encouraged  to use `omitempty`. For example:

```go
type myCacheItem struct {
	Name string `json:"name",omitempty`
}
```

It is possible to use core types such as `pkg.Package` as long as they support the standard `json` serialization,
but this is discouraged in order to decouple changes to them from affecting the information stored in the cache.

To get a cache for this type:
```go
resolver := cache.GetResolver[myCacheItem]("myCacheName", "v1")
```

Using the `resolver` is a single call, which manages checking for items in the cache, expiry times,
and if not found invoking the callback to populate the cache and return a value:
```go
data := resolver.Resolve("some/cache/key", func() (myCacheItem, error) {
	// do things to return a myCacheItem or error
})
```

If it is common that checking for an item will result in errors, and you do not want to re-run the resolve function
when errors are encountered, instead of using `GetResolver`, you can use `GetResolverCachingErrors`, which is useful
for things such as resolving artifacts over a network, where a number of them will not be resolved, and you do not want
to continue to have the expense of running the network resolution. This should be used when it is acceptable a network
outage and cached errors is an acceptable risk.

An example can be seen in the [golang cataloger](../../syft/pkg/cataloger/golang/licenses.go) fetching remote licenses.
