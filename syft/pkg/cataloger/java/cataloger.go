/*
Package java provides a concrete Cataloger implementation for packages relating to the Java language ecosystem.
*/
package java

import (
	"context"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/anchore/syft/internal/archive"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// NewArchiveCataloger returns a new Java archive cataloger object for detecting packages with archives (jar, war, ear, par, sar, jpi, hpi, and native-image formats)
func NewArchiveCataloger(cfg ArchiveCatalogerConfig) pkg.Cataloger {
	if a := cfg.ArchiveSearchConfig; a.MaxDepth != 0 || a.MaxMemoryBytes != 0 || a.MaxDiskBytes != 0 {
		log.Debug("java archive cataloger ignores nested archive depth and limits, set them with syft.CreateSBOMConfig.Archive")
	}
	gap := newGenericArchiveParserAdapter(cfg)

	c := generic.NewCataloger("java-archive-cataloger").
		WithParserByGlobs(gap.parseJavaArchive, archiveFormatGlobs...)

	if cfg.IncludeIndexedArchives {
		// java archives wrapped within zip files
		gzp := newGenericZipWrappedJavaArchiveParser(cfg)
		c.WithParserByGlobs(gzp.parseZipWrappedJavaArchive, genericZipGlobs...)
	}

	if cfg.IncludeUnindexedArchives {
		// java archives wrapped within tar files
		gtp := newGenericTarWrappedJavaArchiveParser(cfg)
		c.WithParserByGlobs(gtp.parseTarWrappedJavaArchive, genericTarGlobs...)
	}

	return &archiveCataloger{cfg: cfg, extractingCataloger: c}
}

// archiveCataloger catalogs java archives two ways. Inside an archive the archive cataloger task has
// extracted, the resolver is that archive's contents and the traversal on the context names the
// archive, so the archive to describe is the one the resolver holds. Everywhere else, archives are
// files in the resolver that this cataloger opens itself.
type archiveCataloger struct {
	cfg                 ArchiveCatalogerConfig
	extractingCataloger *generic.Cataloger
}

func (c *archiveCataloger) Name() string {
	return c.extractingCataloger.Name()
}

func (c *archiveCataloger) Catalog(ctx context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	if trav := archive.TraversalFromContext(ctx); trav != nil {
		return c.catalogExtracted(ctx, trav, resolver)
	}

	if archive.NestedCatalogingEnabled(ctx) {
		// the archive cataloger task extracts every archive and runs this cataloger inside each; opening
		// them here too would catalog each twice
		return nil, nil, nil
	}

	// process archives directly, using the original locally managed java archive extraction
	return c.extractingCataloger.Catalog(ctx, resolver)
}

// catalogExtracted reports the java package of the archive whose contents the resolver holds, if it
// is a java archive. Archives nested inside it are left to the archive cataloger task.
func (c *archiveCataloger) catalogExtracted(ctx context.Context, trav *archive.Traversal, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	if !isJavaArchiveName(trav.Location.Path()) {
		return nil, nil, nil
	}

	parser, err := newExtractedArchiveParser(trav, resolver, c.cfg)
	if err != nil {
		return nil, nil, err
	}

	// link to the jar this one is nested in, as the legacy recursion does: a DEPENDENCY_OF edge from
	// parse, and Parent on whatever does not already have one
	parent := enclosingJavaPackage(trav)
	pkgs, relationships, err := parser.parse(ctx, parent)
	if parent != nil {
		for i := range pkgs {
			if metadata, ok := pkgs[i].Metadata.(pkg.JavaArchive); ok && metadata.Parent == nil {
				metadata.Parent = parent
				pkgs[i].Metadata = metadata
			}
		}
	}
	if err != nil {
		// attributed to the archive, as the generic cataloger attributes a parser failure to its file
		return pkgs, relationships, unknown.New(trav.Location, err)
	}
	return pkgs, relationships, nil
}

// enclosingJavaPackage returns the main java package of the archive the traversal's archive is nested
// in, if there is one. Of the java packages located at an archive, the main one carries the archive's
// own virtual path; those found from embedded pom files carry it with their group and artifact appended.
func enclosingJavaPackage(trav *archive.Traversal) *pkg.Package {
	if trav.Parent == nil {
		return nil
	}
	virtualPath := archive.VirtualPath(trav.Parent.Location)
	for _, p := range trav.Parent.Packages {
		if metadata, ok := p.Metadata.(pkg.JavaArchive); ok && metadata.VirtualPath == virtualPath {
			return &p
		}
	}
	return nil
}

// isJavaArchiveName reports whether the path matches the globs this cataloger opens files by.
func isJavaArchiveName(path string) bool {
	for _, glob := range archiveFormatGlobs {
		if ok, _ := doublestar.Match(glob, path); ok {
			return true
		}
	}
	return false
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
