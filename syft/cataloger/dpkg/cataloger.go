/*
Package dpkg provides a concrete Cataloger implementation for Debian package DB status files.
*/
package dpkg

import (
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/cataloger/common"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/scope"
	"io"
)

// Cataloger catalogs pkg.DebPkg Package Types defined in DPKG status files.
type Cataloger struct {
	cataloger common.GenericCataloger
}

// New returns a new Deb package cataloger object.
func New() *Cataloger {
	globParsers := map[string]common.ParserFn{
		"**/var/lib/dpkg/status": parseDpkgStatus,
	}

	return &Cataloger{
		cataloger: common.NewGenericCataloger(nil, globParsers),
	}
}

// Name returns a string that uniquely describes this cataloger.
func (c *Cataloger) Name() string {
	return "dpkg-cataloger"
}

// SelectFiles returns a set of discovered DPKG status files from the user content source.
func (c *Cataloger) SelectFiles(resolver scope.FileResolver) []file.Reference {
	return c.cataloger.SelectFiles(resolver)
}

// Catalog returns the Packages indexed from all DPKG status files discovered.
func (c *Cataloger) Catalog(contents map[file.Reference]io.Reader) ([]pkg.Package, error) {
	return c.cataloger.Catalog(contents)
}
