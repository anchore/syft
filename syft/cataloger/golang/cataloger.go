/*
Package golang provides a concrete Cataloger implementation for go.mod files.
*/
package golang

import (
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/cataloger/common"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/scope"
	"io"
)

// Cataloger catalogs pkg.GoModulePkg Package Types defined in go.mod files.
type Cataloger struct {
	cataloger common.GenericCataloger
}

// New returns a new Go module cataloger object.
func New() *Cataloger {
	globParsers := map[string]common.ParserFn{
		"**/go.mod": parseGoMod,
	}

	return &Cataloger{
		cataloger: common.NewGenericCataloger(nil, globParsers),
	}
}

// Name returns a string that uniquely describes this cataloger.
func (c *Cataloger) Name() string {
	return "go-cataloger"
}

// SelectFiles returns a set of discovered go.mod files from the user content source.
func (c *Cataloger) SelectFiles(resolver scope.FileResolver) []file.Reference {
	return c.cataloger.SelectFiles(resolver)
}

// Catalog returns the Packages indexed from all go.mod files discovered.
func (c *Cataloger) Catalog(contents map[file.Reference]io.Reader) ([]pkg.Package, error) {
	return c.cataloger.Catalog(contents)
}
