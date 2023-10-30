package alpm

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

const catalogerName = "alpmdb-cataloger"

// NewAlpmdbCataloger returns a new cataloger object initialized for arch linux pacman database flat-file stores.
func NewAlpmdbCataloger() *generic.Cataloger {
	return generic.NewCataloger(catalogerName).
		WithParserByGlobs(parseAlpmDB, pkg.AlpmDBGlob)
}
