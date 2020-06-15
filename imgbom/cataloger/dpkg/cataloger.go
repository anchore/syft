package dpkg

import (
	"github.com/anchore/imgbom/imgbom/cataloger/common"
	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/tree"
)

type Cataloger struct {
	cataloger common.GenericCataloger
}

func NewCataloger() *Cataloger {
	pathParsers := map[string]common.ParserFn{
		"/var/lib/dpkg/status": parseDpkgStatus,
	}

	return &Cataloger{
		cataloger: common.NewGenericCataloger(pathParsers, nil),
	}
}

func (a *Cataloger) Name() string {
	return "dpkg-cataloger"
}

func (a *Cataloger) SelectFiles(trees []tree.FileTreeReader) []file.Reference {
	return a.cataloger.SelectFiles(trees)
}

func (a *Cataloger) Catalog(contents map[file.Reference]string) ([]pkg.Package, error) {
	return a.cataloger.Catalog(contents, a.Name())
}
