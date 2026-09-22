# internal/index

A key-split (radix) index over strings, and a forward/reverse pair of them that answers prefix and
suffix lookups. Ported from a prototype directory-scan package and kept close to the original so the
two can be diffed.

## Types

- `KeySplitIndex[T]` / `Node[T]`: a radix tree. Each node holds at most one value and splits its
  children on the longest common prefix of their keys, so `pom.xml` and `pom.properties` share a
  `pom.` node. Reads take a read lock per node; writes upgrade to a write lock only where the tree
  changes. `KeySplitIndex` also marshals to and from a flat JSON object of key → value.
- `PrefixSuffix[T]`: two `KeySplitIndex` values, one keyed by the string and one by its reverse, so
  `ByPrefix("pom")` and `BySuffix(".jar")` are both a single descent followed by a collect.

## Operations

| call | answers |
|---|---|
| `Get(key)` | the value at exactly `key` |
| `Set(key, v)` / `Update(key, fn)` | store, or read-modify-write, the value at `key` |
| `ByPrefix(p)` | every value whose key starts with `p` |
| `BySuffix(s)` (PrefixSuffix only) | every value whose key ends with `s` |

Values are whatever the caller stores; `internal/archive` stores `[]*node` per base name because a
name repeats across directories.

## Where it is used

`internal/archive.Index` keeps one `PrefixSuffix[[]*node]` of files by base name. A cataloger glob
whose last segment is a literal, `*suffix` or `prefix*` (nearly all of them: `**/*.jar`,
`**/pom.properties`) is answered from it instead of by walking every path.

## Notes

- Lookups are byte-wise; `reverse` works on runes so a multi-byte name reverses correctly.
- `lock.go` returns unlock functions rather than exposing `Unlock`, which is how a node tells a read
  lock from a write lock when deciding whether to upgrade.
- `_find`, `_collect` and `_makeNodeP` are the prototype's internals and are left with its naming.
