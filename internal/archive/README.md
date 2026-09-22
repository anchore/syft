# internal/archive

Opens one archive as its own filesystem so the ordinary catalogers can run against its contents.
The archive cataloger task (`internal/task/archive_tasks.go`) drives the recursion; this package
does everything for a single archive.

## Flow

```
Extract(ctx, reader, fileSystemID, archivePath, limiter, exclusions)
  acquireContent   read in place if the reader is already seekable, else hold in memory / write to disk
  identifyFormat   mholt/archives sniffing first, end-of-central-directory fallback for stub-prefixed zips
  extractInto      every entry -> EntryStore (excluded entries are never stored)
  NewIndex         file.Resolver over the store's entries
  digestsOf        SHA-1 of the archive itself
```

`Extract` returns `nil` for content that is not an archive, `ErrDiskLimitReached` when the archive's
own bytes cannot be placed, and otherwise an `Extracted` whose `Cleanup` releases everything.

## Where bytes live

| what | in memory while... | otherwise |
|---|---|---|
| the archive's own bytes | the reader is not seekable and memory admits them | `<workdir>/archive` |
| its entries' content | memory admits them | `<workdir>/entries`, one file for all entries, located by offset |

Anything already random-access (an `*os.File`, or a nested archive read out of its parent's store)
is used in place and costs nothing. The work directory is created only when something is written,
so most archives never touch the filesystem. Held archive bytes are released as soon as extraction
and digesting finish.

## Limits

`Limits` bound what one scan holds *at once*; each falls as archives are released. For both limits,
positive is the bound, zero forbids the resource, negative is unbounded.

- `Limiter` is scan-wide; `Charge` is one archive's draw on it. Bytes are charged as they land,
  never from declared sizes.
- Memory refused → content moves to disk. Disk refused → the archive's own bytes cannot be placed
  (`ErrDiskLimitReached`, archive skipped) or an entry cannot be stored (`Extracted.Truncated`,
  the entries stored so far are still cataloged).
- Index bookkeeping is approximated as `approxIndexBytesPerEntry` (2 KiB) plus name length per
  entry, charged to memory and falling back to disk so a zero memory limit still indexes.

## Index (the resolver)

Paths are archive-relative with no leading slash. Directories implied by entry paths exist for
`HasPath`. Links resolve inside the archive only; a glob matching a link and its target returns one
location. `FilesByGlob` narrows by the pattern's last segment through a base-name index
(`internal/index`) when it is a literal, `*suffix` or `prefix*`, and otherwise matches every file
with doublestar.

## Other pieces

- `Exclusions`: the scan's `**/` exclusion patterns, matched against each entry path and its parent
  directories at extraction time. Sourced from `source.PathExcluder`.
- `Traversal`: put on the context by the task so a cataloger (java) knows which archive it is inside.
  `VirtualPath(location)` builds the `outer.war:WEB-INF/lib/inner.jar` style chain from the
  `ArchivePath` the index stamps on every location.
- `entryHeader`: cleans entry names to archive-relative paths, drops device nodes and fifos, and
  refuses names longer than PATH_MAX.
