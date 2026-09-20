package archive

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"io"
	"path/filepath"

	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
)

// StoreResolverFactory builds an indexed resolver over one archive's entries. Injected so this
// package does not depend on the internal fileresolver package.
type StoreResolverFactory func(*EntryStore, Overflow) (file.Resolver, IndexResult, error)

// Overflow names what the resolver built over one archive's entries must know.
type Overflow struct {
	// FileSystemID is the identifier of the filesystem the archive file itself lives on (a layer
	// digest, or blank), inherited unchanged down the nesting chain, stamped onto every Location.
	FileSystemID string

	// ArchivePath is the colon-delimited chain of archive paths from the scan root to this archive,
	// stamped onto every Location. It keeps identically-named files in different archives from
	// colliding in the coordinate-keyed SBOM tables.
	ArchivePath string

	// Charge is this archive's draw on the resource limiter; nil enforces nothing. The index keeps more
	// per entry than the store does (one node per path component), so it charges for what it keeps
	// rather than letting the store estimate for it.
	Charge *Charge
}

// IndexResult reports what indexing one archive's entries produced.
type IndexResult struct {
	// Truncated reports that the budget refused an index record and the remaining entries were never
	// indexed. What was indexed is complete and usable.
	Truncated bool
}

// archiveDigestHashes are the digests taken of an archive as a whole: SHA-1 alone, matching what the
// java archive cataloger reports for a jar.
var archiveDigestHashes = []crypto.Hash{crypto.SHA1}

// digestsOf takes the archive's own digests in one pass over the acquired content, which the java
// cataloger reads when it can no longer open the archive itself. A failure is logged and returns
// nothing: an archive that cataloged fine is not discarded for a missing hash.
func digestsOf(ctx context.Context, content Content, accessPath string) []file.Digest {
	if _, err := content.Reader.Seek(0, io.SeekStart); err != nil {
		log.WithFields("archive", accessPath, "error", err).Trace("unable to rewind archive content for digests")
		return nil
	}
	digests, err := intFile.NewDigestsFromFile(ctx, io.NopCloser(content.Reader), archiveDigestHashes)
	if err != nil {
		log.WithFields("archive", accessPath, "error", err).Trace("unable to take archive digests")
		return nil
	}
	return digests
}

// ExtractedArchive is a standalone, fully-indexed filesystem built from an extracted archive.
type ExtractedArchive struct {
	// Resolver is an indexed resolver over the extracted contents, its Locations stamped with
	// FileSystemID.
	Resolver file.Resolver

	// Digests are the digests of the archive file itself, taken while its bytes were in hand.
	Digests []file.Digest
	// FileSystemID is the filesystem the archive file itself lives on, inherited unchanged down the
	// nesting chain.
	FileSystemID string
	// Result reports how much was extracted and whether a bound truncated it. A truncated archive
	// still yields a usable Resolver over what was written before the bound; see ExtractionResult.
	Result ExtractionResult

	// content is this archive's own bytes, in memory or spilled to disk. Retained until Cleanup so the
	// bytes the limiter counts as held stay reachable and lazy readers keep their backing.
	content Content

	cleanup func()
}

// Cleanup removes the temp directory backing this archive's filesystem and releases what it held
// against the limiter. Safe to call more than once.
func (e *ExtractedArchive) Cleanup() {
	if e == nil || e.cleanup == nil {
		return
	}
	// close before removing the work directory, so the overflow blob handle is released while the file
	// still exists. A resolver holding nothing open is not an io.Closer.
	if closer, ok := e.Resolver.(io.Closer); ok {
		if err := closer.Close(); err != nil {
			log.WithFields("fsid", e.FileSystemID, "error", err).Trace("unable to close archive resolver")
		}
	}
	e.cleanup()
	e.cleanup = nil
	// drop the last reference so the limit falls as the bytes become collectable
	e.content = Content{}
}

// ExtractToResolver holds the given archive content (in memory while the memory limit admits it, on
// disk once it does not), extracts it, and returns a standalone indexed resolver over its contents
// whose Locations are stamped with fileSystemID and archivePath. Returns (nil, nil) when the content
// is not an extractable archive. The caller owns the result and must call Cleanup on it. Everything
// the archive holds is charged to one limiter handle and released by Cleanup.
//
// Reaching a limit never waits for capacity: the walk descends before it unwinds, so a containing
// archive still holds its content while its children are cataloged, and nothing would be released
// while this one waited. Content that cannot be admitted yields ErrDiskLimitReached.
//
// Reaching a bound part way through is not an error: the ExtractedArchive is indexed over the partial
// contents and Result.Truncated() reports it. Any other non-nil error means nothing usable was
// produced.
func ExtractToResolver(ctx context.Context, content io.Reader, archiveAccessPath, fileSystemID, archivePath string, extractors []Extractor, limiter *Limiter, newStoreResolver StoreResolverFactory, notify Notify) (*ExtractedArchive, error) {
	// created only if this archive writes something; most never do
	workDir := NewWorkDir(ctx)

	charge := limiter.Charge()

	var held Content
	cleanup := func() {
		if closeErr := held.Close(); closeErr != nil {
			log.WithFields("archive", archiveAccessPath, "error", closeErr).Trace("unable to close archive content")
		}
		held = Content{}
		workDir.Remove()
		charge.Release()
	}

	held, err := acquireContent(content, workDir, archiveFileName(archiveAccessPath), charge, notify)
	if err != nil {
		cleanup()
		if notify != nil && errors.Is(err, ErrDiskLimitReached) {
			notify(Skipped{Archive: archiveAccessPath, Reason: "content would exceed the disk limit"})
		}
		// unwrapped so the caller can attribute an ErrDiskLimitReached skip to this archive
		return nil, err
	}

	extractor := FindExtractor(ctx, extractors, held)
	if extractor == nil {
		// not extractable (e.g. an executable that matched a broad mime filter)
		cleanup()
		return nil, nil
	}

	resolver, result, err := storeAndIndex(ctx, extractor, held, workDir, fileSystemID, archivePath, archiveAccessPath, charge, newStoreResolver, notify)
	if err != nil {
		cleanup()
		return nil, err
	}

	return &ExtractedArchive{
		Resolver:     resolver,
		Digests:      digestsOf(ctx, held, archiveAccessPath),
		FileSystemID: fileSystemID,
		Result:       result,
		content:      held,
		cleanup:      cleanup,
	}, nil
}

// inPlaceContent is content already random-access and already charged for by the archive holding it.
// A nested archive arrives as a reader over one entry of its parent's EntryStore supporting Read,
// Seek and ReadAt, so it is read where it lies rather than copied or spilled again.
//
// A marker method rather than a type assertion, because the concrete type belongs to the fileresolver
// package, which this one does not import. Nothing else satisfies it.
type inPlaceContent interface {
	io.Reader
	io.ReaderAt
	io.Seeker

	// OverflowArchiveEntry marks a reader over one entry of an archive's EntryStore.
	OverflowArchiveEntry()
}

// acquireContent gets one archive's bytes ready for random access: content already held by a parent
// archive is used in place, anything else goes through the limiter. In-place content is charged
// nothing, since the parent already charged for those bytes and releases them on its own Cleanup.
func acquireContent(r io.Reader, workDir *WorkDir, name string, charge *Charge, notify Notify) (Content, error) {
	if entry, ok := r.(inPlaceContent); ok {
		return Content{Name: name, Reader: entry}, nil
	}
	return holdContent(r, workDir, name, charge, notify)
}

// archiveFileName derives a safe basename for the saved archive, preserving compound extensions
// (e.g. ".tar.gz") so format detection can identify it. "..", empty and root are refused, since
// joining them to the work directory would name the directory above; the destination is rechecked
// before the write.
func archiveFileName(accessPath string) string {
	name := filepath.Base(accessPath)
	if name == "" || name == "." || name == ".." || name == string(filepath.Separator) {
		return "archive"
	}
	return name
}

// storeAndIndex puts the archive's entries into an EntryStore and builds the resolver over them.
//
// ErrDiskLimitReached travels unwrapped so the caller can attribute the skip to this archive.
func storeAndIndex(ctx context.Context, extractor Extractor, held Content, workDir *WorkDir, fsID, archivePath, accessPath string, charge *Charge, newStoreResolver StoreResolverFactory, notify Notify) (file.Resolver, ExtractionResult, error) {
	var result ExtractionResult

	store := NewEntryStore(workDir, accessPath, notify)

	result, err := extractor.Extract(ctx, held, store, charge)
	if err != nil {
		if closeErr := store.Close(); closeErr != nil {
			log.WithFields("archive", fsID, "error", closeErr).Trace("unable to close archive entry store")
		}
		return nil, result, fmt.Errorf("unable to extract archive %q: %w", fsID, err)
	}

	// the disk limit refused the first byte, so every entry is content-less: skip the archive rather
	// than catalog it as empty. An archive that stored some entries is a truncation instead.
	if result.Truncation == TruncatedByDiskLimit && store.OnDisk() == 0 {
		if closeErr := store.Close(); closeErr != nil {
			log.WithFields("archive", fsID, "error", closeErr).Trace("unable to close archive entry store")
		}
		return nil, result, ErrDiskLimitReached
	}

	resolver, indexed, err := newStoreResolver(store, Overflow{
		FileSystemID: fsID,
		ArchivePath:  archivePath,
		Charge:       charge,
	})
	if err != nil {
		if closeErr := store.Close(); closeErr != nil {
			log.WithFields("archive", fsID, "error", closeErr).Trace("unable to close archive entry store")
		}
		return nil, result, fmt.Errorf("unable to index extracted archive %q: %w", fsID, err)
	}

	// an extraction already stopped at a bound keeps that reason: it names where the archive was cut
	// short, and the index only ran out of budget behind it
	if indexed.Truncated && !result.Truncated() {
		result.Truncation = TruncatedByIndexLimit
	}
	if notify != nil && result.Truncated() {
		notify(Truncated{Archive: accessPath, Reason: result.Truncation})
	}
	return resolver, result, nil
}
