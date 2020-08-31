/*
Package java provides a concrete Cataloger implementation for Java archives (jar, war, ear, jpi, hpi formats).
*/
package java

import (
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/cataloger/common"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/scope"
	"io"
)

// Cataloger catalogs pkg.JavaPkg and pkg.JenkinsPluginPkg Package Types defined in java archive files.
type Cataloger struct {
	cataloger common.GenericCataloger
}

// New returns a new Java archive cataloger object.
func New() *Cataloger {
	globParsers := make(map[string]common.ParserFn)
	for _, pattern := range archiveFormatGlobs {
		globParsers[pattern] = parseJavaArchive
	}

	return &Cataloger{
		cataloger: common.NewGenericCataloger(nil, globParsers),
	}
}

// Name returns a string that uniquely describes this cataloger.
func (c *Cataloger) Name() string {
	return "java-cataloger"
}

// SelectFiles returns a set of discovered Java archive files from the user content source.
func (c *Cataloger) SelectFiles(resolver scope.FileResolver) []file.Reference {
	return c.cataloger.SelectFiles(resolver)
}

// Catalog returns the Packages indexed from all Java archive files discovered.
func (c *Cataloger) Catalog(contents map[file.Reference]io.Reader) ([]pkg.Package, error) {
	return c.cataloger.Catalog(contents)
}
