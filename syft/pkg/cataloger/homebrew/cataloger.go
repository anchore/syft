package homebrew

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

func NewCataloger() pkg.Cataloger {
	return generic.NewCataloger("homebrew-cataloger").
		WithParserByGlobs(
			parseHomebrewPackage,
			"**/Cellar/*/*/.brew/*.rb",
			"**/Homebrew/Library/Taps/*/*/Formula/*.rb",
		)
}
