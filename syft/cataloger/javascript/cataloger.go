package npm

import (
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/cataloger/common"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/scope"
)

type Cataloger struct {
	cataloger common.GenericCataloger
}

func NewCataloger() *Cataloger {
	globParsers := map[string]common.ParserFn{
		"**/package-lock.json": parsePackageLock,
	}

	return &Cataloger{
		cataloger: common.NewGenericCataloger(nil, globParsers),
	}
}

func (a *Cataloger) Name() string {
	return "npm-cataloger"
}

func (a *Cataloger) SelectFiles(resolver scope.FileResolver) []file.Reference {
	return a.cataloger.SelectFiles(resolver)
}

func (a *Cataloger) Catalog(contents map[file.Reference]string) ([]pkg.Package, error) {
	return a.cataloger.Catalog(contents, a.Name())
}
