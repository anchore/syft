package alpm

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

const CatalogerName = "alpmdb-cataloger"

func NewAlpmdbCataloger() *generic.Cataloger {
	return generic.NewCataloger(CatalogerName).
		WithParserByGlobs(parseAlpmDB, pkg.AlpmDBGlob)
}
