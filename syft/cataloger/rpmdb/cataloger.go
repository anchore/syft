/*
Package rpmdb provides a concrete Cataloger implementation for RPM "Package" DB files.
*/
package rpmdb

import (
	"github.com/anchore/syft/syft/cataloger/common"
)

// NewRpmdbCataloger returns a new RPM DB cataloger object.
func NewRpmdbCataloger() *common.GenericCataloger {
	globParsers := map[string]common.ParserFn{
		"**/var/lib/rpm/Packages": parseRpmDB,
	}
	return common.NewGenericCataloger(nil, globParsers, "rpmdb-cataloger")
}
