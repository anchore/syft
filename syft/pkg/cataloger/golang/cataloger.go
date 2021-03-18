/*
Package golang provides a concrete Cataloger implementation for go.mod files.
*/
package golang

import (
	"github.com/anchore/syft/syft/pkg/cataloger/common"
)

// NewGoModCataloger returns a new Go module cataloger object.
func NewGoModCataloger() *common.GenericCataloger {
	globParsers := map[string]common.ParserFn{
		"**/go.mod": parseGoMod,
	}

	return common.NewGenericCataloger(nil, globParsers, "go-cataloger")
}
