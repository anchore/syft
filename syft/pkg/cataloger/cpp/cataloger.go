package cpp

import (
	"github.com/anchore/syft/syft/pkg/cataloger/common"
)

// NewConanfileCataloger returns a new C++ Conanfile cataloger object.
func NewConanfileCataloger() *common.GenericCataloger {
	globParsers := map[string]common.ParserFn{
		"**/conanfile.txt": parseConanfile,
		"**/conan.lock":    parseConanlock,
	}

	return common.NewGenericCataloger(nil, globParsers, "conan-cataloger")
}
