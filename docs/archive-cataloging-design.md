# Recursive Archive Cataloging — Design

Status: **approved, in implementation**
Branch: `feat/recursive-archive-combined`

## Background

Syft can scan inside Java archives (JAR/WAR/EAR, including shaded JARs) but ignores the
contents of generic archives (`.tar`, `.tar.gz`/`.tgz`, `.zip`, `.apk`, `.gem`, `.iso`, …)
found in a scanned directory or image. Tracked by issues
[#246](https://github.com/anchore/syft/issues/246),
[#1379](https://github.com/anchore/syft/issues/1379),
[#2407](https://github.com/anchore/syft/issues/2407).

Two community PRs attempted this and are **superseded** by this design:

- **#4044** (@Rupikz) — recursion at the `fileresolver` layer.
- **#4761** (@toabctl) — a composite resolver + orchestrator wired into `CreateSBOM`.

Both author's commits are preserved in this branch's history for credit; their
approaches are replaced for the reasons below.

## Why the prior approaches were rejected

Search in syft *is* an index lookup. `FilesByPath`/`FilesByGlob`
(`syft/internal/fileresolver/filetree_resolver.go`) call
`SearchContext.SearchByPath(...)` and then `r.Index.Get(ref)`; a file that is not in
*that resolver's own* `filetree.Index` causes the lookup to error and the file is
**silently skipped**. A composite/wrapped resolver that merges archive contents without
merging a real index therefore excludes files from indexing and breaks search. Pushing
recursion into the directory resolver also smears archive contents into the parent's
tree/chroot and forces a signature change on every `NewFromDirectory` caller.

## Core principle

**Each archive is treated as its own fully-indexed, standalone filesystem** — exactly how
syft already treats container image layers. Extract the archive to a temp directory and
build a resolver with `fileresolver.NewFromDirectory(tempDir, …)`, which produces a
complete `Tree` + `Index` + `SearchContext`. No resolver merging, no shared index.

## Design decisions (locked)

1. **Detection is content-based** via `internal/file.IdentifyArchive` (catches `.tgz`,
   renamed archives, etc.).
2. **A new `archive-cataloger` Task** (`internal/task/`) drives
   detect → extract → run the cataloger sub-pipeline → recurse. It is added to the
   package-cataloger task group, **before** relationship/unknowns tasks.
3. **Provenance is expressed only via file-level `CONTAINS` relationships** in the first
   iteration: `From` = the archive file's `Coordinates`, `To` = each nested file/package.
   No changes to `Location`/`Coordinates`/metadata schema.
4. **`Coordinates` is never modified** — it must remain a comparable two-string struct
   (used as `map[file.Coordinates]…` keys throughout `sbom.Artifacts` and as the
   `LocationData` key in `LocationSet`).
5. **Node identity uses a per-archive `FileSystemID`** (an *existing* `Coordinates`
   field — no struct change). The chain rule is:

   ```
   childFSID = parentFSID == "" ? archiveAccessPath
                                : parentFSID + "/" + archiveAccessPath
   ```

   - Uses the archive Location's **AccessPath**.
   - For non-image sources the root FSID is empty, so the chain starts with the relative
     archive path (e.g. `some/path/to.zip/some/nested/path.tar.gz`). Image sources start
     from the layer digest (e.g. `<layerDigest>/some/path/to.zip/…`).
   - The `FiletreeResolver` carries a `fileSystemID` and stamps it onto every returned
     `Location`, the same pattern image-layer resolvers already use. This keeps
     same-named files in different archives from colliding in the coordinate-keyed tables,
     with no post-processing in catalogers.
6. **Java is left as-is in phase 1.** The generic archive cataloger recurses only into
   **non-JAR** types; detection excludes the formats the Java cataloger owns
   (`.jar/.war/.ear/.par/.sar/.nar/.jpi/.hpi/.kar/.far/.lpkg/.rar/.zap`). Unifying JARs
   into the generic mechanism is deferred.
7. **Disabled by default.** Opt-in via `--archive-max-depth` / `SYFT_ARCHIVE_MAX_DEPTH`
   (default `0`), plus the extraction safety limits (max extraction size, file count,
   total bytes) carried over from the prior work.

## Reused from the prior PRs

- `internal/archive/extractor.go` — archive extractor + zip-bomb / size-limit guards.
- `syft/cataloging/archive_search.go` — the `ArchiveSearchConfig` (depth + limits).
- `syft/pkg/cataloger/java/parse_pom_xml.go` — skip `META-INF/maven/*/pom.xml` phantom
  packages.

## Implementation phases

| Phase | Work |
|------|------|
| 0 | Remove PR-4044's resolver recursion and PR-4761's composite/orchestrator; restore the 2-arg `NewFromDirectory`. Keep the items listed under "Reused" above. |
| 1 | `FiletreeResolver.fileSystemID` + stamp on all Location-returning call sites; add `NewFromDirectoryWithFS(root, base, fileSystemID, …)` (existing `NewFromDirectory` delegates with `""`). |
| 2 | `extractToResolver(...)` — extract to a temp dir and build a standalone indexed resolver with the computed `childFSID`. |
| 3 | The `archive-cataloger` Task — detect (non-JAR) archives, run the package/file cataloger sub-pipeline into a scratch builder, merge into the shared builder, emit `CONTAINS` edges, and recurse to `MaxDepth`. |
| 4 | Wire the task into `makeTaskGroups`; add `--archive-max-depth` (default 0) and limits. |
| 5 | Tests: FSID stamping, extractor limits/zip-slip, nested-fixture FSID/relationship/dedup assertions, CLI integration. |
