/*
Package dpkg provides a concrete Cataloger implementation for Debian package DB status files.
*/
package dpkg

import (
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/cataloger/common"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/scope"
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
func (a *Cataloger) Name() string {
	return "dpkg-cataloger"
}

// SelectFiles returns a set of discovered DPKG status files from the user content source.
func (a *Cataloger) SelectFiles(resolver scope.FileResolver) []file.Reference {
	return a.cataloger.SelectFiles(resolver)
}

// Catalog returns the Packages indexed from all DPKG status files discovered.
func (a *Cataloger) Catalog(contents map[file.Reference]string) ([]pkg.Package, error) {
	return a.cataloger.Catalog(contents, a.Name())
}
