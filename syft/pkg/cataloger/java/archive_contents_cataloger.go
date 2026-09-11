package java

import (
	"context"
	"fmt"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/anchore/syft/internal/archive"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/java/internal/maven"
)

const ArchiveContentsCatalogerName = "java-archive-contents-cataloger"

// NewArchiveContentsCataloger returns a java archive cataloger for the world after extraction: it
// reads an archive's already-extracted filesystem rather than opening the archive itself.
//
// It is a second cataloger rather than a mode of the first because the two answer different
// questions. The archive-reading cataloger asks "is this file a jar?" of every file in a scan; this
// one asks "is the filesystem I have been handed a jar?", which is the only form the question can
// take once something else owns extraction. That inversion is also why it cannot be a parameter:
// when the archive cataloger task hands a jar's contents to the sub-pipeline, the jar file is one
// level up and already behind us.
//
// What it does not do is recurse. The task that extracted this archive will meet the archives inside
// it on its own, and one mechanism owning recursion is the whole point - see
// syft/java-archive-nesting#single-owner-of-archive-recursion.
func NewArchiveContentsCataloger(cfg ArchiveCatalogerConfig) pkg.Cataloger {
	return archiveContentsCataloger{cfg: cfg}
}

type archiveContentsCataloger struct {
	cfg ArchiveCatalogerConfig
}

func (c archiveContentsCataloger) Name() string {
	return ArchiveContentsCatalogerName
}

// Catalog reports the java package of the archive whose contents this resolver holds, if it is a java
// archive at all.
//
// Nothing outside an archive is cataloged. Without a traversal on the context there is no archive to
// describe - the identity of a java archive lives half in the file (its name, its digests) and half
// in its contents (the manifest, the poms), and the file half arrives only on the traversal.
func (c archiveContentsCataloger) Catalog(ctx context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	trav := archive.TraversalFromContext(ctx)
	if trav == nil {
		return nil, nil, nil
	}

	if !isJavaArchiveName(trav.Location.Path()) {
		// the same rule the archive-reading cataloger applies through its globs: a .zip is an archive
		// but it is not a java archive, and its contents are not a jar's contents
		return nil, nil, nil
	}

	parser, err := newArchiveContentsParser(trav, resolver, c.cfg)
	if err != nil {
		return nil, nil, err
	}

	pkgs, relationships, err := parser.parse(ctx, nil)
	if err != nil {
		// attributed to the archive rather than returned bare, the way the generic cataloger attributes
		// a parser's failure to the file it was parsing. An archive that turns out to hold no java
		// package at all reports exactly that, and the scan carries on.
		return pkgs, relationships, unknown.New(trav.Location, err)
	}
	return pkgs, relationships, nil
}

// newArchiveContentsParser builds the same parser the archive-reading cataloger uses, over the
// archive's extracted filesystem instead of over the archive file. Identity comes from the traversal:
// the location and virtual path it already carries, the archive's filename for the name and version
// fallbacks, and the digests taken when the archive was extracted.
func newArchiveContentsParser(trav *archive.Traversal, resolver file.Resolver, cfg ArchiveCatalogerConfig) (*archiveParser, error) {
	if resolver == nil {
		return nil, fmt.Errorf("no resolver for the contents of %q", trav.VirtualPath)
	}
	return &archiveParser{
		entries:  newResolverEntries(resolver, trav.Digests),
		location: trav.Location,
		// the colon-delimited chain the task composed, which is the identity already-published SBOMs
		// carry for a nested java package
		virtualPath: trav.VirtualPath,
		fileInfo:    newJavaArchiveFilename(archiveFileNameOf(trav)),
		// recursion belongs to the task that extracted this archive
		detectNested: false,
		cfg:          cfg,
		maven:        maven.NewResolver(nil, cfg.mavenConfig()),
	}, nil
}

// archiveFileNameOf returns the archive's own file name, which is where a jar's name and version come
// from when its manifest does not say. The last element of the virtual path rather than of the real
// path, so a chain and a plain scan agree.
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

// isJavaArchiveName reports whether the path is one of the java archive formats, by the same glob
// list the archive-reading cataloger registers against.
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
