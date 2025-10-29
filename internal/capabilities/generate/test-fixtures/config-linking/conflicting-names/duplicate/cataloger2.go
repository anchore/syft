package duplicate

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

type Config2 struct {
	Option2 string
}

func NewDuplicateCataloger2(cfg Config2) pkg.Cataloger {
	return generic.NewCataloger("duplicate-cataloger").
		WithParserByGlobs(parse2, "**/*.json")
}

func parse2(path string, reader any) ([]pkg.Package, []pkg.Relationship, error) {
	return nil, nil, nil
}
