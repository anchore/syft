# internal/archive

Opens one archive as its own filesystem so the ordinary catalogers can run against its contents.
The archive cataloger task (`internal/task/archive_tasks.go`) drives the recursion; this package
does everything for a single archive.

## Flow

```
Extract(ctx, reader, archiveCoordinates, limiter, exclusions) -> *Resolver
  acquire          read in place if the reader is already seekable, else hold in memory / spill to disk
  identifyFormat   internal/file.IdentifyArchive first, end-of-central-directory fallback for stub-prefixed zips
  Resolver.extract every entry -> entryHeader -> Resolver.add (excluded entries are never stored)
  digestsOf        SHA-1 of the archive itself
```

`Extract` returns `nil` for content that is not an archive (a bare compression format such as a
gzipped file that is not a tar counts as not an archive), `ErrDiskLimitReached` when the archive's
own bytes cannot be placed, and otherwise a `Resolver` whose `Cleanup` releases everything.

## Resolver

One type does the work: `Resolver` is fed entries by `Extract`, holds their content, indexes them,
and implements `file.Resolver` over the result. Each entry is a `node` carrying its header and a
`blob`; the archive's own bytes, when they have to be held at all, are one more blob.

Every location it returns extends the archive's coordinates: `RealPath` and `FileSystemID` stay
those of the outermost archive on the scanned filesystem, and `FullPath` is the `!/`-delimited
chain down to the entry (`/app.war!/WEB-INF/lib/dep.jar!/META-INF/MANIFEST.MF`). `LocalPath` is the
entry's path within this archive.

## Where bytes live

Blobs are held in memory while the memory limit admits them and in one spill file per archive
(`archive-spill-*`) once it does not; when a chunk is refused, everything held in memory moves to
the file first. The file is created on first use, so most archives never touch the filesystem, and
blobs are located in it by offset with no framing of their own. It goes under the scan's temp root
when the context carries one (`internal/tmpdir`), otherwise the system temp directory.

Anything already random-access (an `*os.File`, or a nested archive read out of its parent's
resolver) is used in place and costs nothing, so only a top-level stream is ever copied. Its memory
is refunded once it is extracted and digested; bytes it spilled wait for `Cleanup` with the entries.

## Limits

`Limits` bound what one scan holds *at once*; each falls as archives are released. For both limits,
positive is the bound, zero forbids the resource, negative is unbounded.

- `Limiter` is scan-wide; a `charge` is one archive's draw on it. Bytes are charged as they land,
  never from declared sizes.
- Memory refused → content moves to disk. Disk refused → the archive's own bytes cannot be placed
  (`ErrDiskLimitReached`, archive skipped) or an entry cannot be stored (`Resolver.Truncated`, the
  entries stored so far are still cataloged).
- Index bookkeeping is approximated as `approxIndexBytesPerEntry` (2 KiB) per node, listed or
  implied by an entry's path, plus name length. It lives in memory, so it is charged to the memory
  limit, spilling held content to make room; only a zero memory limit lets it fall back to the disk
  budget so that configuration still indexes. An entry whose index cost is refused is dropped like
  one whose content is, and marks the resolver `Truncated`.
- `Budget` bounds the bytes decompressed under one top-level archive, summed over everything nested
  in it. Unlike `Limits` it never refills, so a recursive bomb whose every level fits the limits
  still ends (`errBudgetSpent`, the resolver is `Truncated`).
- `Limiter.Peak` reports the most held at once over the scan, for reporting.

## Hostile archives

Nothing an archive declares is trusted. Content is charged chunk by chunk as it decompresses, so a
deflate or gzip bomb stops at the disk limit with the entry dropped whole. Every node is charged
against the memory limit, including directories implied by deep paths, so an archive of millions of
tiny entries or of a few entries with 4 KiB names stops at the memory limit. A recursive bomb stops
at the `Budget`. Names longer than PATH_MAX are refused, and nesting stops at the task's `MaxDepth`.
See the bomb tests in `extract_test.go`.

## Lookup

Entries are indexed in a stereoscope `filetree.FileTree` + `filetree.Index` and searched with
`filetree.SearchContext`, the same index the directory and image resolvers use. A query may name an
entry by its full path or by its `LocalPath` (leading slash optional); a full path into another
archive in the scan names nothing. Directories implied by entry paths exist for `HasPath` but are
never files. The last entry at a path wins over earlier
duplicates, as it does on extraction; a file and a directory at one path keep the first.

Links resolve inside the archive only, as the file tree resolves them: a hard link names its target
from the archive root. A lookup matching a link and its target returns one location, with
`AccessPath` the full path matched and `FullPath` that of the file read. Dangling and cyclic links are not
files. `AllLocations` enumerates every non-directory path, links included. Answers are sorted by path.

## Other pieces

- `Exclusions`: the scan's exclusion patterns, of which only the `**/` shape means the same thing
  re-rooted at an archive. Matched against each entry path and its parent directories at extraction
  time. `syft.CreateSBOM` passes the source's patterns to the task, which builds one `Exclusions`
  for the scan.
- `Traversal`: put on the context by the task so a cataloger (java) knows which archive it is inside,
  what its digests are, and which packages describe its parent. `VirtualPath(location)` converts a
  location's `FullPath` to the java cataloger's colon-delimited `app.war:WEB-INF/lib/inner.jar`
  form, escaping `%` and `:` in entry names. `Container` and `EntryCoordinates` split and build the
  coordinates of files within archives (the SPDX and CycloneDX formats use them too); `OwnerContainers` and
  `OwnedCoordinates` map package-owned file paths to coordinates in the right archive.
- `WithNestedCataloging` / `NestedCatalogingEnabled`: `syft.CreateSBOM` marks the context when the
  archive task is running, so the java cataloger leaves nested archives to the task instead of
  opening them itself.
- `entryHeader`: keeps regular files, directories and links only (no devices or fifos), cleans entry names to
  archive-relative paths, refuses names longer than PATH_MAX or containing control characters, line
  separators or the `!/` archive path separator (marking the resolver truncated), and drops header
  fields nothing reads (PAX records, user and group names, sub-second and access times) since the
  header is held for the life of the archive.
