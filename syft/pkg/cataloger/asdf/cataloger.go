package asdf

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// NewInstalledFileCataloger returns a new cataloger for installed asdf-managed files
func NewInstalledFileCataloger() pkg.Cataloger {
	return generic.NewCataloger("asdf-cataloger").
		WithParserByGlobs(parseAsdfInstallations, asdfInstallGlob)
}
