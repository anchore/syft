package apkdb

import (
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/cataloger/common"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/scope"
)

// Cataloger catalogs pkg.ApkPkg Package Types defined in Alpine DB files.
type Cataloger struct {
	cataloger common.GenericCataloger
}

// New returns a new Alpine DB cataloger object.
func New() *Cataloger {
	globParsers := map[string]common.ParserFn{
		"**/lib/apk/db/installed": parseApkDB,
	}

	return &Cataloger{
		cataloger: common.NewGenericCataloger(nil, globParsers),
	}
}

// Name returns a string that uniquely describes this cataloger.
func (a *Cataloger) Name() string {
	return "apkdb-cataloger"
}

// SelectFiles returns a set of discovered Alpine DB files from the user content source.
func (a *Cataloger) SelectFiles(resolver scope.FileResolver) []file.Reference {
	return a.cataloger.SelectFiles(resolver)
}

// Catalog returns the Packages indexed from all Alpine DB files discovered.
func (a *Cataloger) Catalog(contents map[file.Reference]string) ([]pkg.Package, error) {
	return a.cataloger.Catalog(contents, a.Name())
}
