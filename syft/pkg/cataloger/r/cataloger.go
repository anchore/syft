package r

import (
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

const catalogerName = "r-package-cataloger"

// NewPackageCataloger returns a new R cataloger object based on detection of R package DESCRIPTION files.
func NewPackageCataloger() *generic.Cataloger {
	return generic.NewCataloger(catalogerName).
		WithParserByGlobs(parseDescriptionFile, "**/DESCRIPTION")
}
