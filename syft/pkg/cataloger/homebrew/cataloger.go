package homebrew

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

func NewCataloger() pkg.Cataloger {
	return generic.NewCataloger("homebrew-cataloger").
		WithParserByGlobs(
			parseHomebrewFormula,
			// forumulas are located at $(brew --repository)/Cellar
			"**/Cellar/*/*/.brew/*.rb",
			// taps are located at $(brew --repository)/Library/Taps
			"**/Library/Taps/*/*/Formula/*.rb",
		)
}
