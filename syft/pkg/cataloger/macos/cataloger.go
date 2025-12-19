package macos

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

func NewAppCataloger() pkg.Cataloger {
	return generic.NewCataloger("macos-app-cataloger").
		WithParserByGlobs(parseInfoPlist, "**/*.app/Contents/Info.plist")
}
