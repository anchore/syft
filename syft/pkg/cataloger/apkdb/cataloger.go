/*
Package apkdb provides a concrete Cataloger implementation for Alpine DB files.
*/
package apkdb

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// NewApkdbCataloger returns a new Alpine DB cataloger object.
func NewApkdbCataloger() *generic.Cataloger {
	globParsers := map[string]generic.Parser{
		pkg.ApkDBGlob: parseApkDB,
	}

	return generic.NewCataloger(nil, globParsers, "apkdb-cataloger")
}
