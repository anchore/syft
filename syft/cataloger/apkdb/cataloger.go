/*
Package apkdb provides a concrete Cataloger implementation for Alpine DB files.
*/
package apkdb

import (
	"github.com/anchore/syft/syft/cataloger/common"
)

// NewApkdbCataloger returns a new Alpine DB cataloger object.
func NewApkdbCataloger() *common.GenericCataloger {
	globParsers := map[string]common.ParserFn{
		"**/lib/apk/db/installed": parseApkDB,
	}

	return common.NewGenericCataloger(nil, globParsers, "apkdb-cataloger")
}
