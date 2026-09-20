package java

import (
	"context"
	"fmt"
	"strings"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/anchore/syft/internal/archive"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/tmpdir"
	"github.com/anchore/syft/syft/file"
)

// archiveSource is one java archive to describe: where its entries are read from, and the identity
// that does not live inside them - the archive's own location, the colon-delimited virtual path
// SBOMs carry, and the file name that name and version fall back to.
//
// Two of these exist because two things can own extraction. When this cataloger owns it, the archive
// is a file it copies to a temp dir and reads as a zip. When the archive cataloger task owns it, the
// archive has already been extracted and indexed, and arrives as a resolver plus the traversal
// describing the file it came from. Everything past this point - which manifest wins, how
// pom.properties decides identity, license discovery - is logic over a source, so it runs unchanged
// either way.
type archiveSource struct {
	entries     archiveEntries
	location    file.Location
	virtualPath string
	fileInfo    archiveFilename

	// contentPath is the directory nested archives are extracted into. Set only when this cataloger
	// opened the archive itself: recursing needs somewhere to unzip into, and an already-extracted
	// archive has none. The archive file itself is held by zipEntries.
	contentPath string
}

// newFileArchiveSource copies the archive to a temp dir and reads its central directory, for a scan
// where nothing has already extracted it. The returned cleanup must run even when an error is
// returned.
func newFileArchiveSource(ctx context.Context, reader file.LocationReadCloser) (archiveSource, func(), error) {
	// the full virtual path of this archive: when the archive cataloger task drove us here, the context
	// traversal supplies the containing chain; otherwise the reader path already carries any
	// colon-delimited nesting from this cataloger's own recursion
	virtualPath := archive.TraversalFromContext(ctx).VirtualPathOf(reader.Path())

	// fetch the last element of the virtual path
	virtualElements := strings.Split(virtualPath, ":")
	currentFilepath := virtualElements[len(virtualElements)-1]

	td := tmpdir.FromContext(ctx)
	if td == nil {
		return archiveSource{}, func() {}, fmt.Errorf("no temp dir factory in context")
	}
	contentPath, archivePath, cleanupFn, err := saveArchiveToTmp(td, currentFilepath, reader)
	if err != nil {
		return archiveSource{}, cleanupFn, fmt.Errorf("unable to process java archive: %w", err)
	}

	entries, err := newZipEntries(ctx, archivePath)
	if err != nil {
		return archiveSource{}, cleanupFn, err
	}

	return archiveSource{
		entries:     entries,
		location:    reader.Location,
		virtualPath: virtualPath,
		fileInfo:    newJavaArchiveFilename(currentFilepath),
		contentPath: contentPath,
	}, cleanupFn, nil
}

// newExtractedArchiveSource describes the archive whose extracted contents the given resolver holds.
// Nothing is copied or reopened, and identity comes from the traversal: the location, the chain the
// archive cataloger task composed, the file name, and the digests taken at extraction - none of which
// are inside the archive.
func newExtractedArchiveSource(trav *archive.Traversal, resolver file.Resolver) (archiveSource, error) {
	if resolver == nil {
		return archiveSource{}, fmt.Errorf("no resolver for the contents of %q", trav.VirtualPath)
	}
	return archiveSource{
		entries:     newResolverEntries(resolver, trav.Digests),
		location:    trav.Location,
		virtualPath: trav.VirtualPath,
		fileInfo:    newJavaArchiveFilename(archiveFileNameOf(trav)),
	}, nil
}

// archiveFileNameOf returns the archive's own file name, where a jar's name and version come from
// when its manifest does not say. It takes the last element of the virtual path rather than the real
// path, so a nested chain and a plain scan agree.
func archiveFileNameOf(trav *archive.Traversal) string {
	name := trav.VirtualPath
	if name == "" {
		name = trav.Location.Path()
	}
	for i := len(name) - 1; i >= 0; i-- {
		if name[i] == ':' || name[i] == '/' {
			return name[i+1:]
		}
	}
	return name
}

// isJavaArchiveName reports whether the path is one of the java archive formats, by the same globs
// this cataloger registers against when it is the one opening files.
func isJavaArchiveName(path string) bool {
	for _, glob := range archiveFormatGlobs {
		if ok, err := doublestar.Match(glob, path); err == nil && ok {
			return true
		}
		if ok, err := doublestar.Match(glob, "/"+path); err == nil && ok {
			return true
		}
	}
	log.WithFields("path", path).Trace("archive contents are not a java archive")
	return false
}
