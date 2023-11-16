/*
Package java provides a concrete Cataloger implementation for packages relating to the Java language ecosystem.
*/
package java

import (
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// NewArchiveCataloger returns a new Java archive cataloger object for detecting packages with archives (jar, war, ear, par, sar, jpi, hpi, and native-image formats)
func NewArchiveCataloger(cfg Config) *generic.Cataloger {
	gap := newGenericArchiveParserAdapter(cfg)

	c := generic.NewCataloger("java-archive-cataloger").
		WithParserByGlobs(gap.parseJavaArchive, archiveFormatGlobs...)

	if cfg.SearchIndexedArchives {
		// java archives wrapped within zip files
		gzp := newGenericZipWrappedJavaArchiveParser(cfg)
		c.WithParserByGlobs(gzp.parseZipWrappedJavaArchive, genericZipGlobs...)
	}

	if cfg.SearchUnindexedArchives {
		// java archives wrapped within tar files
		gtp := newGenericTarWrappedJavaArchiveParser(cfg)
		c.WithParserByGlobs(gtp.parseTarWrappedJavaArchive, genericTarGlobs...)
	}
	return c
}

// NewPomCataloger returns a cataloger capable of parsing dependencies from a pom.xml file.
// Pom files list dependencies that maybe not be locally installed yet.
func NewPomCataloger() *generic.Cataloger {
	return generic.NewCataloger("java-pom-cataloger").
		WithParserByGlobs(parserPomXML, "**/pom.xml")
}

// NewGradleLockfileCataloger returns a cataloger capable of parsing dependencies from a gradle.lockfile file.
// Note: Older versions of lockfiles aren't supported yet
func NewGradleLockfileCataloger() *generic.Cataloger {
	return generic.NewCataloger("java-gradle-lockfile-cataloger").
		WithParserByGlobs(parseGradleLockfile, gradleLockfileGlob)
}
