package javascript

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

func NewJavaScriptCataloger() pkg.Cataloger {
	return generic.NewCataloger("javascript-cataloger").
		WithParserByGlobs(parse, "**/*.js")
}

func parse(path string, reader any) ([]pkg.Package, []pkg.Relationship, error) {
	return nil, nil, nil
}
