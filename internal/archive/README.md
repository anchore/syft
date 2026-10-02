# internal/archive

Opens one archive as its own filesystem so the ordinary catalogers can run against its contents.
The archive cataloger task (`internal/task/archive_tasks.go`) drives the recursion; this package
does everything for a single archive.

## Flow

```
Extract(ctx, reader, fileSystemID, archivePath, limiter, exclusions) -> *Resolver
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
- `Limiter.Peak` reports the most held at once over the scan, for reporting.

## Hostile archives

Nothing an archive declares is trusted. Content is charged chunk by chunk as it decompresses, so a
deflate or gzip bomb stops at the disk limit with the entry dropped whole. Every node is charged
against the memory limit, including directories implied by deep paths, so an archive of millions of
tiny entries or of a few entries with 4 KiB names stops at the memory limit. Names longer than
PATH_MAX are refused, link chains stop after `maxLinkHops`, and nesting stops at the task's
`MaxDepth`. See the bomb tests in `extract_test.go`.

## Lookup

Paths are archive-relative with no leading slash; a leading slash on a query is tolerated. Directories
implied by entry paths exist for `HasPath` but are never files, and every node is linked to its
parent and children. The first entry at a path wins over later duplicates.

Links resolve inside the archive only, up to `maxLinkHops` hops, which also ends a cycle. A glob or
path lookup matching a link and its target returns one location: the file's own path when it
matched, otherwise the lowest-sorting link, with `AccessPath` naming the path matched and `RealPath`
the file read. A dangling link keeps its own path and reads as empty. `FilesByMIMEType` answers only
with files holding bytes, since a link has nothing to sniff; `AllLocations` enumerates every path,
links included. Answers are sorted by path.

`FilesByGlob` (glob.go) parses a pattern once, cached (bounded by `maxCachedGlobs`), into segments.
A brace group inside a segment, `g{o,o.exe}`, makes that segment a set of alternatives; only a group
spanning `/` expands the whole pattern. The literal text at either end of every alternative is looked
up in a base-name index (`internal/index`): files for the last segment, directories for the rest, so
`**/one/two/**/[a-z]thing` is narrowed to what lies under directories named `two` or to files ending
in `thing`, whichever is smaller (a file-name lookup of `narrowEnough` or fewer is taken as is). Each
candidate is then verified segment by segment up its parent chain with `path.Match`. `**/<name>`,
`**/*<suffix>`, `**/<prefix>*` and brace sets of those are answered from the index alone. Only a
pattern with no literal text anywhere, such as `**/[lm]*`, is matched against every file.

## Other pieces

- `Exclusions`: the scan's exclusion patterns, of which only the `**/` shape means the same thing
  re-rooted at an archive. Matched against each entry path and its parent directories at extraction
  time. `syft.CreateSBOM` passes the source's patterns to the task, which builds one `Exclusions`
  for the scan.
- `Traversal`: put on the context by the task so a cataloger (java) knows which archive it is inside
  and what its digests are. `VirtualPath(location)` builds the `outer.war:WEB-INF/lib/inner.jar`
  style chain from the `ArchivePath` the resolver stamps on every location, escaping colons in entry
  names.
- `WithNestedCataloging` / `NestedCatalogingEnabled`: `syft.CreateSBOM` marks the context when the
  archive task is running, so the java cataloger leaves nested archives to the task instead of
  opening them itself.
- `entryHeader`: keeps regular files, directories and links only (no devices or fifos), cleans entry names to
  archive-relative paths, refuses names longer than PATH_MAX or containing NUL, and drops header
  fields nothing reads (PAX records, user and group names, sub-second and access times) since the
  header is held for the life of the archive.
