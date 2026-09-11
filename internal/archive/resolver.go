package archive

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/tmpdir"
	"github.com/anchore/syft/syft/file"
)

// ResolverFactory builds an indexed resolver over one archive's overflow tar. It is injected (rather
// than calling syft/internal/fileresolver directly) so this module-root package does not depend on
// the syft-subtree internal fileresolver package.
//
// It reports what indexing found as well as the resolver, because a tar-family archive is copied
// wholesale and its entries are first counted where the tar is indexed.
type ResolverFactory func(Overflow) (file.Resolver, IndexResult, error)

// StoreResolverFactory builds a resolver over an archive's entries rather than over a tar of them.
//
// Where a ResolverFactory can only index content already written to a file - its index IS that file's
// offsets - this one indexes the entries themselves, so an archive small enough to stay in memory
// never reaches the disk and one that outgrows memory moves its bytes without the index changing.
// Injected the same way and for the same reason: this package must not depend on the resolver
// packages it hands work to.
type StoreResolverFactory func(*EntryStore, Overflow) (file.Resolver, IndexResult, error)

// Overflow names what one archive's entries were written into, and what the resolver built over them
// must know.
type Overflow struct {
	// RootDir is the archive's logical root: an empty directory that every entry's path is reported
	// relative to. It exists on disk, and stays empty - nothing is written into it - because the
	// resolver relativizes an entry's path against a real root the way a directory scan does, and
	// that is what keeps a path in the SBOM relative to its own archive rather than naming the
	// scan's scratch space.
	RootDir string

	// TarPath is the one file holding every entry of this archive, indexed by seek offset.
	TarPath string

	// FileSystemID is the identifier of the filesystem the archive file itself lives on (a layer
	// digest, or blank), inherited unchanged down the nesting chain, stamped onto every Location.
	FileSystemID string

	// ArchivePath is the colon-delimited chain of archive paths from the scan root to this archive,
	// stamped onto every Location. It is what keeps identically-named files in different archives
	// from colliding in the coordinate-keyed SBOM tables.
	ArchivePath string
}

// IndexResult reports what indexing one archive's overflow tar produced.
type IndexResult struct {
	// Records is how many entries the archive's filesystem holds.
	Records int

	// Truncated reports that indexing stopped before the end of the tar, which now means only one
	// thing: the tar itself ends part way through an entry because the disk limit stopped the write.
	// What was indexed is complete and usable; there is simply less of it.
	Truncated bool
}

// archiveDigestHashes are the digests taken of an archive file as a whole. SHA-1 alone, matching
// what the java archive cataloger has always reported for a jar, because these are the digests it
// reads when it can no longer open the archive itself.
var archiveDigestHashes = []crypto.Hash{crypto.SHA1}

// digestsOf takes the archive's own digests from the content already acquired. One pass over a
// seekable source - memory or an overflow file - and it replaces a read the java cataloger used to
// do for itself, so it is not new work so much as work moved to where the bytes already are.
//
// A failure is logged and returns nothing: a digest is metadata about a package, and an archive
// whose contents cataloged fine should not be discarded because its hash could not be taken.
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
	// Resolver is an indexed resolver over the extracted contents; its Locations are stamped with FileSystemID.
	Resolver file.Resolver

	// Digests are the digests of the archive file itself, taken while its bytes were in hand.
	Digests []file.Digest
	// FileSystemID is the identifier of the filesystem the archive file itself lives on (inherited unchanged down the nesting chain).
	FileSystemID string
	// ArchivePath is the colon-delimited chain of archive paths from the scan root to this archive.
	ArchivePath string
	// Result reports how much was extracted and whether a configured bound truncated the
	// extraction. A truncated archive still yields a usable Resolver over whatever was written
	// before the bound; see ExtractionResult.
	Result ExtractionResult

	// content is this archive's own bytes, held in memory or overflowed to disk. It is kept here rather
	// than dropped after extraction for two reasons: content held in memory must stay reachable for
	// as long as the memory limit accounts for it as held, otherwise the limiter measures something
	// the garbage collector has already taken back; and openers over the extracted tree are heading
	// towards reading lazily, which cannot work if the backing bytes are gone.
	content Content

	cleanup func()
}

// Cleanup removes the temp directory backing this archive's filesystem and releases what this
// archive was holding against the scan's limiter, so both limits fall by exactly what it took. Safe
// to call more than once.
func (e *ExtractedArchive) Cleanup() {
	if e == nil || e.cleanup == nil {
		return
	}
	// close the resolver before the work directory is removed, so the entry store's overflow blob
	// handle is released while the file it points at still exists. A resolver that holds nothing open
	// - the tar path opens its file per read - does not implement io.Closer and is skipped.
	if closer, ok := e.Resolver.(io.Closer); ok {
		if err := closer.Close(); err != nil {
			log.WithFields("fsid", e.FileSystemID, "error", err).Trace("unable to close archive resolver")
		}
	}
	e.cleanup()
	e.cleanup = nil
	// drop the last reference to content held in memory, so the limit falling and the bytes becoming
	// collectable happen together
	e.content = Content{}
}

// ExtractToResolver holds the given archive content - in memory while the memory limit admits it, on
// disk once it does not - extracts it, and returns a standalone indexed resolver over its contents
// whose Locations are stamped with the given fileSystemID (the filesystem the archive file lives on)
// and archivePath (the colon-delimited archive nesting chain from the scan root to this archive). It
// returns (nil, nil) when the content is not a supported/extractable archive. The caller owns the
// returned value and must call Cleanup on it.
//
// Everything this archive holds is charged to one handle against the scan's limiter and released by
// Cleanup, which processArchive already defers past the sub-pipeline and past recursion - so the
// limits fall exactly where the resources are freed, and nothing new has to remember to do it.
//
// Reaching a limit never waits for capacity. The walk descends before it unwinds, so a containing
// archive is still holding its content while its children are cataloged and nothing will be released
// while this archive waits: waiting would be a deadlock dressed as backpressure. Content that cannot
// be admitted yields ErrDiskLimitReached and the caller skips the archive.
//
// Reaching a bound part way through is not an error either: the returned ExtractedArchive is indexed
// over the partial contents and Result.Truncated() reports it, so the caller can still catalog what
// was extracted. Any other non-nil error means nothing usable was produced.
func ExtractToResolver(ctx context.Context, content io.Reader, archiveAccessPath, fileSystemID, archivePath string, extractors []Extractor, limiter *Limiter, limits ExtractionLimits, newResolver ResolverFactory, newStoreResolver StoreResolverFactory, notify Notify) (*ExtractedArchive, error) {
	workDir, removeWorkDir, err := newWorkDir(ctx)
	if err != nil {
		return nil, err
	}

	charge := limiter.Charge()
	limits.Charge = charge

	var held Content
	cleanup := func() {
		if closeErr := held.Close(); closeErr != nil {
			log.WithFields("archive", archiveAccessPath, "error", closeErr).Trace("unable to close archive content")
		}
		held = Content{}
		removeWorkDir()
		charge.Release()
	}

	held, err = acquireContent(content, workDir, archiveFileName(archiveAccessPath), charge, notify)
	if err != nil {
		cleanup()
		if notify != nil && errors.Is(err, ErrDiskLimitReached) {
			notify(Skipped{Archive: archiveAccessPath, Reason: "content would exceed the disk limit"})
		}
		// ErrDiskLimitReached travels unwrapped so the caller can attribute the skip to this archive
		return nil, err
	}

	extractor := FindExtractor(ctx, extractors, held)
	if extractor == nil {
		// not an archive we can extract (e.g. an executable that happened to match a broad mime filter)
		cleanup()
		return nil, nil
	}

	resolver, result, err := overflowAndIndex(ctx, extractor, held, workDir, fileSystemID, archivePath, archiveAccessPath, limits, newResolver, newStoreResolver, notify)
	if err != nil {
		cleanup()
		return nil, err
	}

	return &ExtractedArchive{
		Resolver:     resolver,
		Digests:      digestsOf(ctx, held, archiveAccessPath),
		FileSystemID: fileSystemID,
		ArchivePath:  archivePath,
		Result:       result,
		content:      held,
		cleanup:      cleanup,
	}, nil
}

// workDirName is the prefix given to the directory holding one archive's content and entries. Named
// so a scan's leftovers are recognizable, and matched by the tests that sample what is on disk.
const workDirName = "syft-archive"

// newWorkDir creates the directory one archive's content and entries are written into, under the
// scan's own temp root when the context carries one.
//
// The root is where every other cataloger that spills to disk already writes (see internal/tmpdir),
// which is what makes a scan's temp files land where the caller configured them and get removed
// together if an archive's own cleanup is ever missed. A context with no root - a caller reaching
// this package directly - still gets a directory, from the same place it would have come from
// before.
func newWorkDir(ctx context.Context) (string, func(), error) {
	if td := tmpdir.FromContext(ctx); td != nil {
		dir, cleanup, err := td.NewChild(workDirName) //nolint:gocritic // cleanup is returned to the caller, not deferred here
		if err != nil {
			return "", nil, fmt.Errorf("unable to create temp dir for archive extraction: %w", err)
		}
		return dir, cleanup, nil
	}

	dir, err := os.MkdirTemp("", workDirName+"-")
	if err != nil {
		return "", nil, fmt.Errorf("unable to create temp dir for archive extraction: %w", err)
	}
	return dir, func() {
		if rmErr := os.RemoveAll(dir); rmErr != nil {
			log.WithFields("dir", dir, "error", rmErr).Trace("unable to remove archive temp dir")
		}
	}, nil
}

// overflowAndIndex writes one archive's entries into the tar in workDir and builds the resolver over it.
//
// Errors travel unwrapped where the caller has to tell them apart: ErrDiskLimitReached attributes a
// skip to this archive, and everything else is a failure of this archive alone.
func overflowAndIndex(ctx context.Context, extractor Extractor, held Content, workDir, fsID, archivePath, accessPath string, limits ExtractionLimits, newResolver ResolverFactory, newStoreResolver StoreResolverFactory, notify Notify) (file.Resolver, ExtractionResult, error) {
	if newStoreResolver != nil {
		return storeAndIndex(ctx, extractor, held, workDir, fsID, archivePath, accessPath, limits, newStoreResolver, notify)
	}
	var result ExtractionResult

	// the archive's logical root, which stays empty: entries live in the tar beside it, and this is
	// only what their paths are reported relative to
	contentsDir := filepath.Join(workDir, "contents")
	if err := os.MkdirAll(contentsDir, 0o755); err != nil {
		return nil, result, fmt.Errorf("unable to create contents dir for archive %q: %w", fsID, err)
	}

	overflow, err := newOverflowTar(filepath.Join(workDir, overflowTarName))
	if err != nil {
		return nil, result, err
	}

	result, err = extractor.Extract(ctx, held, overflow, limits)
	if closeErr := overflow.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, result, fmt.Errorf("unable to extract archive %q: %w", fsID, err)
	}

	// nothing of this archive could be placed: the disk limit refused its first byte, so there is
	// nowhere for its content to go and the archive is skipped rather than cataloged as empty. This is
	// where the terminal reading of the disk limit lands now that a nested archive is read where it
	// lies: its own bytes are never copied, so they are never the thing refused, and what is refused
	// instead is the file its entries are written into. An archive that placed SOME of its entries is
	// a truncation, not a skip - see ExtractionResult.
	if result.Truncation == TruncatedByDiskLimit && result.BytesWritten == 0 {
		return nil, result, ErrDiskLimitReached
	}

	resolver, indexed, err := newResolver(Overflow{
		RootDir:      contentsDir,
		TarPath:      overflow.Path(),
		FileSystemID: fsID,
		ArchivePath:  archivePath,
	})
	if err != nil {
		return nil, result, fmt.Errorf("unable to index extracted archive %q: %w", fsID, err)
	}

	// the count of entries the archive's filesystem holds is the index's to report, not the writer's:
	// a tar-family archive is copied wholesale and never walked, and an exclusion pattern drops
	// entries after they were written
	result.FilesExtracted = indexed.Records
	if indexed.Truncated && !result.Truncated() {
		// the tar ends part way through an entry and nothing recorded why. The disk limit is the only
		// bound that can end a write early and it names itself, so reaching here means a ragged tar
		// with no attributed cause - reported as a truncation without claiming which bound did it.
		result.Truncation = TruncatedByLimit
	}

	return resolver, result, nil
}

// inPlaceContent is content that is already random-access on a file this scan wrote and is already
// accounted for by the archive that wrote it.
//
// A nested archive arrives as a reader over one entry of its parent's overflow tar, and that reader is
// Read, Seek AND ReadAt - which is everything an archive format needs, a zip's central directory
// included. So it is read in place rather than copied into memory or overflowed again: the payoff for
// choosing tar as the storage format, and the reason an inner zip needs no special handling.
//
// Declared as a marker method rather than by asserting on the reader's type, because the type belongs
// to the resolver package that this one deliberately does not import. Nothing else in the process
// answers to it, so nothing else is read in place by accident.
type inPlaceContent interface {
	io.Reader
	io.ReaderAt
	io.Seeker

	// OverflowArchiveEntry marks a reader over one entry of an archive's overflow tar.
	OverflowArchiveEntry()
}

// acquireContent gets one archive's bytes ready to be read at random, which is what every archive
// format needs: it reads content already sitting in a file this scan wrote in place, and otherwise
// routes the bytes through the limiter - held in memory while the memory limit admits them, overflowed
// to disk once it does not.
//
// Content read in place is charged nothing, because nothing new is held: the bytes are part of the
// parent archive's tar, which the parent already charged for and releases on its own Cleanup. Its
// handle is the caller's to close, as it was before this ever reached here.
func acquireContent(r io.Reader, workDir, name string, charge *Charge, notify Notify) (Content, error) {
	if entry, ok := r.(inPlaceContent); ok {
		return Content{Name: name, Reader: entry}, nil
	}
	return holdContent(r, workDir, name, charge, notify)
}

// archiveFileName derives a safe basename for the saved archive, preserving compound extensions
// (e.g. ".tar.gz") so format detection has the best chance to identify the archive.
//
// ".." is refused along with the empty and root cases: Base returns it for an access path ending in
// it, and joining it to the work directory would name the directory above. overflowContent checks its
// destination as well, so this is the earlier of two refusals rather than the only one.
func archiveFileName(accessPath string) string {
	name := filepath.Base(accessPath)
	if name == "" || name == "." || name == ".." || name == string(filepath.Separator) {
		return "archive"
	}
	return name
}

// storeAndIndex is the entry-store path: the archive's entries go into an EntryStore, which holds
// them in memory while the memory limit admits them, and the resolver is built over the entries.
//
// Compared to the tar path this writes nothing for an archive that fits in memory - no tar to encode,
// no file to index - and where the archive does not fit, the content moves without the index being
// rebuilt.
func storeAndIndex(ctx context.Context, extractor Extractor, held Content, workDir, fsID, archivePath, accessPath string, limits ExtractionLimits, newStoreResolver StoreResolverFactory, notify Notify) (file.Resolver, ExtractionResult, error) {
	var result ExtractionResult

	// the archive's logical root, which stays empty: entries live in the store, and this is only what
	// their paths are reported relative to
	contentsDir := filepath.Join(workDir, "contents")
	if err := os.MkdirAll(contentsDir, 0o755); err != nil {
		return nil, result, fmt.Errorf("unable to create contents dir for archive %q: %w", fsID, err)
	}

	store := NewEntryStore(workDir, accessPath, notify)

	result, err := extractor.Extract(ctx, held, store, limits)
	if err != nil {
		if closeErr := store.Close(); closeErr != nil {
			log.WithFields("archive", fsID, "error", closeErr).Trace("unable to close archive entry store")
		}
		return nil, result, fmt.Errorf("unable to extract archive %q: %w", fsID, err)
	}

	// nothing of this archive could be placed: the disk limit refused its first byte, so the entries
	// it holds are content-less husks and the archive is skipped rather than cataloged as empty. The
	// same terminal reading of the disk limit the tar path takes, measured the way this path stores
	// its content - an archive that placed SOME of its entries, in memory or on disk, is a truncation.
	if result.Truncation == TruncatedByDiskLimit && store.OnDisk() == 0 {
		if closeErr := store.Close(); closeErr != nil {
			log.WithFields("archive", fsID, "error", closeErr).Trace("unable to close archive entry store")
		}
		return nil, result, ErrDiskLimitReached
	}

	resolver, indexed, err := newStoreResolver(store, Overflow{
		RootDir:      contentsDir,
		FileSystemID: fsID,
		ArchivePath:  archivePath,
	})
	if err != nil {
		if closeErr := store.Close(); closeErr != nil {
			log.WithFields("archive", fsID, "error", closeErr).Trace("unable to close archive entry store")
		}
		return nil, result, fmt.Errorf("unable to index extracted archive %q: %w", fsID, err)
	}

	result.FilesExtracted = indexed.Records
	if notify != nil && result.Truncated() {
		notify(Truncated{Archive: accessPath, Reason: result.Truncation})
	}
	return resolver, result, nil
}
