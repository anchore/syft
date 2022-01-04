/*
Package java provides a concrete Cataloger implementation for Java archives (jar, war, ear, par, jpi, hpi formats).
*/
package java

import (
	"github.com/anchore/syft/syft/pkg/cataloger/common"
)

// NewJavaCataloger returns a new Java archive cataloger object.
func NewJavaCataloger() *common.GenericCataloger {
	globParsers := make(map[string]common.ParserFn)

	// java archive formats
	for _, pattern := range archiveFormatGlobs {
		globParsers[pattern] = parseJavaArchive
	}

	// java archives wrapped within zip files
	for _, pattern := range genericZipGlobs {
		globParsers[pattern] = parseZipWrappedJavaArchive
	}

	// java archives wrapped within tar files
	for _, pattern := range genericTarGlobs {
		globParsers[pattern] = parseTarWrappedJavaArchive
	}

	return common.NewGenericCataloger(nil, globParsers, "java-cataloger")
}
