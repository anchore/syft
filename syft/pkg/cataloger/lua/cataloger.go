/*
Package lua provides a concrete Cataloger implementation for packages relating to the Lua language ecosystem.
*/
package lua

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// NewPackageCataloger returns a new cataloger object for Lua ROck.
func NewPackageCataloger() pkg.Cataloger {
	return generic.NewCataloger("lua-rock-cataloger").
		WithParserByGlobs(parseRockspec, "**/*.rockspec")
}
