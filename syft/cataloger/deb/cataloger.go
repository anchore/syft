/*
Package dpkg provides a concrete Cataloger implementation for Debian package DB status files.
*/
package deb

import (
	"github.com/anchore/syft/syft/cataloger/common"
)

// NewDpkgdbCataloger returns a new Deb package cataloger object.
func NewDpkgdbCataloger() *common.GenericCataloger {
	globParsers := map[string]common.ParserFn{
		"**/var/lib/dpkg/status": parseDpkgStatus,
	}

	return common.NewGenericCataloger(nil, globParsers, "dpkgdb-cataloger")
}
