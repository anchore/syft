/*
Package apkdb provides a concrete Cataloger implementation for Alpine DB files.
*/
package apkdb

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

const catalogerName = "apkdb-cataloger"

// NewApkdbCataloger returns a new Alpine DB cataloger object.
func NewApkdbCataloger() *generic.Cataloger {
	return generic.NewCataloger(catalogerName).
		WithParserByGlobs(parseApkDB, pkg.ApkDBGlob)
}
