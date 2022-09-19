/*
Package swift provides a concrete Cataloger implementation for Podfile.lock files.
*/
package swift

import (
	"github.com/anchore/syft/syft/pkg/cataloger/common"
)

// NewCocoapodsCataloger returns a new Swift Cocoapods lock file cataloger object.
func NewCocoapodsCataloger() *common.GenericCataloger {
	globParsers := map[string]common.ParserFn{
		"**/Podfile.lock": parsePodfileLock,
	}

	return common.NewGenericCataloger(nil, globParsers, "cocoapods-cataloger")
}
