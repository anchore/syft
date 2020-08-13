/*
Package javascript provides a concrete Cataloger implementation for JavaScript ecosystem files (yarn and npm).
*/
package javascript

import (
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/cataloger/common"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/scope"
)

// Cataloger catalogs pkg.YarnPkg and pkg.NpmPkg Package Types defined in package-lock.json and yarn.lock files.
type Cataloger struct {
	cataloger common.GenericCataloger
}

// New returns a new JavaScript cataloger object.
func New() *Cataloger {
	globParsers := map[string]common.ParserFn{
		"**/package-lock.json": parsePackageLock,
		"**/yarn.lock":         parseYarnLock,
	}

	return &Cataloger{
		cataloger: common.NewGenericCataloger(nil, globParsers),
	}
}

// Name returns a string that uniquely describes this cataloger.
func (a *Cataloger) Name() string {
	return "javascript-cataloger"
}

// SelectFiles returns a set of discovered Javascript ecosystem files from the user content source.
func (a *Cataloger) SelectFiles(resolver scope.FileResolver) []file.Reference {
	return a.cataloger.SelectFiles(resolver)
}

// Catalog returns the Packages indexed from all Javascript ecosystem files discovered.
func (a *Cataloger) Catalog(contents map[file.Reference]string) ([]pkg.Package, error) {
	return a.cataloger.Catalog(contents, a.Name())
}
