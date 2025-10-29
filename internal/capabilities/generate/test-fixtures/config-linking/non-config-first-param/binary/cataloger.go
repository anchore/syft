package binary

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

type Parser struct{}

func NewBinaryCataloger(parser Parser) pkg.Cataloger {
	return generic.NewCataloger("binary-cataloger").
		WithParserByGlobs(parse, "**/*")
}

func parse(path string, reader any) ([]pkg.Package, []pkg.Relationship, error) {
	return nil, nil, nil
}
