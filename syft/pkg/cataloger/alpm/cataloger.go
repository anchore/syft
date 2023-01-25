package alpm

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

const catalogerName = "alpmdb-cataloger"

func NewAlpmdbCataloger() *generic.Cataloger {
	return generic.NewCataloger(catalogerName).
		WithParser(parseAlpmDB,
			generic.NewSearch().ByBasename("desc").MustMatchGlob(pkg.AlpmDBGlob),
		)
}
