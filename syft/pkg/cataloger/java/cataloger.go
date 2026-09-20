/*
Package java provides a concrete Cataloger implementation for packages relating to the Java language ecosystem.
*/
package java

import (
	"context"

	"github.com/anchore/syft/internal/archive"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

const ArchiveCatalogerName = "java-archive-cataloger"

// NewArchiveCataloger returns a new Java archive cataloger object for detecting packages with archives (jar, war, ear, par, sar, jpi, hpi, and native-image formats)
func NewArchiveCataloger(cfg ArchiveCatalogerConfig) pkg.Cataloger {
	gap := newGenericArchiveParserAdapter(cfg)

	files := generic.NewCataloger(ArchiveCatalogerName).
		WithParserByGlobs(gap.parseJavaArchive, archiveFormatGlobs...)

	if cfg.IncludeIndexedArchives {
		// java archives wrapped within zip files
		gzp := newGenericZipWrappedJavaArchiveParser(cfg)
		files.WithParserByGlobs(gzp.parseZipWrappedJavaArchive, genericZipGlobs...)
	}

	if cfg.IncludeUnindexedArchives {
		// java archives wrapped within tar files
		gtp := newGenericTarWrappedJavaArchiveParser(cfg)
		files.WithParserByGlobs(gtp.parseTarWrappedJavaArchive, genericTarGlobs...)
	}

	return &archiveCataloger{cfg: cfg, files: files}
}

// archiveCataloger describes java archives from whichever source this scan makes them available in.
//
// Which source that is turns on who owns extraction, and there are only two answers. Inside an
// archive the archive cataloger task extracted, the resolver is that archive's contents and the
// traversal names the file it came from, so the archive to describe is the one this resolver *is*.
// Everywhere else the archives are files in the resolver, and the cataloger opens each itself.
//
// One cataloger rather than one per source, so a package carries the same FoundBy and answers to the
// same --select-catalogers name however the scan was configured.
type archiveCataloger struct {
	cfg   ArchiveCatalogerConfig
	files *generic.Cataloger
}

func (c *archiveCataloger) Name() string {
	return ArchiveCatalogerName
}

func (c *archiveCataloger) Catalog(ctx context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	if trav := archive.TraversalFromContext(ctx); trav != nil {
		return c.catalogExtracted(ctx, trav, resolver)
	}

	if c.cfg.NestedArchivesHandledExternally {
		// every archive in this scan comes back through the archive cataloger task with a traversal
		// naming it, and is described above. Opening archive files here as well would catalog each of
		// them a second time.
		return nil, nil, nil
	}

	return c.files.Catalog(ctx, resolver)
}

// catalogExtracted reports the java package of the archive whose contents this resolver holds, if it
// is a java archive at all.
//
// It does not glob for the archives inside it: the task that extracted this one meets those on its
// own, at the next nesting level. See syft/java-archive-nesting#single-owner-of-archive-recursion.
func (c *archiveCataloger) catalogExtracted(ctx context.Context, trav *archive.Traversal, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	if !isJavaArchiveName(trav.Location.Path()) {
		// the rule the globs apply when this cataloger opens files: a .zip is an archive but not a java
		// archive
		return nil, nil, nil
	}

	src, err := newExtractedArchiveSource(trav, resolver)
	if err != nil {
		return nil, nil, err
	}

	pkgs, relationships, err := newArchiveParser(src, false, c.cfg).parse(ctx, nil)
	if err != nil {
		// attributed to the archive rather than returned bare, as the generic cataloger attributes a
		// parser's failure to the file it was parsing, so the scan carries on
		return pkgs, relationships, unknown.New(trav.Location, err)
	}
	return pkgs, relationships, nil
}

// NewPomCataloger returns a cataloger capable of parsing dependencies from a pom.xml file.
// Pom files list dependencies that maybe not be locally installed yet.
func NewPomCataloger(cfg ArchiveCatalogerConfig) pkg.Cataloger {
	return pomXMLCataloger{
		cfg: cfg,
	}
}

// NewGradleLockfileCataloger returns a cataloger capable of parsing dependencies from a gradle.lockfile file.
// Note: Older versions of lockfiles aren't supported yet
func NewGradleLockfileCataloger() pkg.Cataloger {
	return generic.NewCataloger("java-gradle-lockfile-cataloger").
		WithParserByGlobs(parseGradleLockfile, "**/gradle.lockfile*")
}

// NewJvmDistributionCataloger returns packages representing JDK/JRE installations (of multiple distribution types).
func NewJvmDistributionCataloger() pkg.Cataloger {
	return generic.NewCataloger("java-jvm-cataloger").
		// this is a very permissive glob that will match more than just the JVM release file.
		// we started with "**/{java,jvm}/*/release", but this prevents scanning JVM archive contents (e.g. jdk8u402.zip).
		// this approach lets us check more files for JVM release info, but be rather silent about errors.
		WithParserByGlobs(parseJVMRelease, "**/release")
}
