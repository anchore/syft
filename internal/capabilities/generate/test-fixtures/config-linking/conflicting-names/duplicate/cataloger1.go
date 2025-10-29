package duplicate

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

type Config1 struct {
	Option1 bool
}

func NewDuplicateCataloger1(cfg Config1) pkg.Cataloger {
	return generic.NewCataloger("duplicate-cataloger").
		WithParserByGlobs(parse1, "**/*.txt")
}

func parse1(path string, reader any) ([]pkg.Package, []pkg.Relationship, error) {
	return nil, nil, nil
}
