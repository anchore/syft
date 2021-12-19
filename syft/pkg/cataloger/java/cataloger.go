/*
Package java provides a concrete Cataloger implementation for Java archives (jar, war, ear, jpi, hpi formats).
*/
package java

import (
	"github.com/anchore/syft/syft/pkg/cataloger/common"
)

// NewJavaCataloger returns a new Java archive cataloger object.
func NewJavaCataloger() *common.GenericCataloger {
	globParsers := make(map[string]common.ParserFn)
	for _, pattern := range archiveFormatGlobs {
		globParsers[pattern] = parseJavaArchive
	}

	return common.NewGenericCataloger(nil, globParsers, "java-archive-cataloger")
}

// NewJavaGradleCataloger returns a new Java gradle cataloger object.
func NewJavaGradleCataloger() *common.GenericCataloger {
	globParsers := map[string]common.ParserFn{
                "**/build.gradle": parseJavaGradle,
        }

	return common.NewGenericCataloger(nil, globParsers, "java-gradle-cataloger")
}
