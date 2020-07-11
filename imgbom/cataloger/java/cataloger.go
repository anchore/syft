package java

import (
	"github.com/anchore/imgbom/imgbom/cataloger/common"
	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/imgbom/imgbom/scope"
	"github.com/anchore/stereoscope/pkg/file"
)

type Cataloger struct {
	cataloger common.GenericCataloger
}

func NewCataloger() *Cataloger {
	globParsers := make(map[string]common.ParserFn)
	for _, pattern := range archiveFormatGlobs {
		globParsers[pattern] = parseJavaArchive
	}

	return &Cataloger{
		cataloger: common.NewGenericCataloger(nil, globParsers),
	}
}

func (a *Cataloger) Name() string {
	return "java-cataloger"
}

func (a *Cataloger) SelectFiles(resolver scope.FileResolver) []file.Reference {
	return a.cataloger.SelectFiles(resolver)
}

func (a *Cataloger) Catalog(contents map[file.Reference]string) ([]pkg.Package, error) {
	return a.cataloger.Catalog(contents, a.Name())
}
