# internal/index

A key-split (radix) index over strings, and a forward/reverse pair of them that answers prefix and
suffix lookups. Ported from a prototype directory-scan package, minus its locking and JSON support: the
only consumer builds an index once and then only reads it, so it is not safe for concurrent writes.

## Types

- `KeySplitIndex[T]` / `Node[T]`: a radix tree. Each node holds at most one value and splits its
  children on the longest common prefix of their keys, so `pom.xml` and `pom.properties` share a
  `pom.` node.
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

`internal/archive.Resolver` keeps one `PrefixSuffix[[]*node]` of files by base name, and one of directories. A cataloger glob
whose last segment is a literal, `*suffix` or `prefix*` (nearly all of them: `**/*.jar`,
`**/pom.properties`) is answered from it instead of by walking every path.

## Notes

- Lookups are byte-wise; `reverse` works on runes so a multi-byte name reverses correctly.
- `_find`, `_collect` and `_makeNodeP` are the prototype's internals and are left with its naming.
