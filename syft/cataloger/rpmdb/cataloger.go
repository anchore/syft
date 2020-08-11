package rpmdb

import (
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/cataloger/common"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/scope"
)

// Cataloger catalogs pkg.RpmPkg Package Types defined in RPM DB files.
type Cataloger struct {
	cataloger common.GenericCataloger
}

// New returns a new RPM DB cataloger object.
func New() *Cataloger {
	globParsers := map[string]common.ParserFn{
		"**/var/lib/rpm/Packages": parseRpmDB,
	}

	return &Cataloger{
		cataloger: common.NewGenericCataloger(nil, globParsers),
	}
}

// Name returns a string that uniquely describes this cataloger.
func (a *Cataloger) Name() string {
	return "rpmdb-cataloger"
}

// SelectFiles returns a set of discovered RPM DB files from the user content source.
func (a *Cataloger) SelectFiles(resolver scope.FileResolver) []file.Reference {
	return a.cataloger.SelectFiles(resolver)
}

// Catalog returns the Packages indexed from all RPM DB files discovered.
func (a *Cataloger) Catalog(contents map[file.Reference]string) ([]pkg.Package, error) {
	return a.cataloger.Catalog(contents, a.Name())
}
