package alpm

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/common"
)

// NewAlpmdbCataloger returns a new Alpine DB cataloger object.
func NewAlpmdbCataloger() *common.GenericCataloger {
	globParsers := map[string]common.ParserFn{
		pkg.AlpmDBGlob: parseAlpmDB,
	}

	return common.NewGenericCataloger(nil, globParsers, "alpmdb-cataloger")
}
