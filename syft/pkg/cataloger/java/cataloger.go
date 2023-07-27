/*
Package java provides a concrete Cataloger implementation for Java archives (jar, war, ear, par, sar, jpi, hpi, and native-image formats).
*/
package java

import (
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// NewJavaCataloger returns a new Java archive cataloger object.
func NewJavaCataloger(cfg Config) *generic.Cataloger {
	c := generic.NewCataloger("java-cataloger").
		WithParserByGlobs(parseJavaArchive, archiveFormatGlobs...)

	if cfg.SearchIndexedArchives {
		// java archives wrapped within zip files
		c.WithParserByGlobs(parseZipWrappedJavaArchive, genericZipGlobs...)
	}

	if cfg.SearchUnindexedArchives {
		// java archives wrapped within tar files
		c.WithParserByGlobs(parseTarWrappedJavaArchive, genericTarGlobs...)
	}
	return c
}

// NewJavaPomCataloger returns a cataloger capable of parsing
// dependencies from a pom.xml file.
// Pom files list dependencies that maybe not be locally installed yet.
func NewJavaPomCataloger() *generic.Cataloger {
	return generic.NewCataloger("java-pom-cataloger").
		WithParserByGlobs(parserPomXML, "**/pom.xml")
}

// NewJavaGradleLockfileCataloger returns a cataloger capable of parsing
// dependencies from a gradle.lockfile file.
// older versions of lockfiles aren't supported yet
func NewJavaGradleLockfileCataloger() *generic.Cataloger {
	return generic.NewCataloger("java-gradle-lockfile-cataloger").
		WithParserByGlobs(parseGradleLockfile, gradleLockfileGlob)
}
