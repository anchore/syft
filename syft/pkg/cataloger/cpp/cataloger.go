package cpp

import (
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

const catalogerName = "conan-cataloger"

// NewConanCataloger returns a new C++ conanfile.txt and conan.lock cataloger object.
func NewConanCataloger() *generic.Cataloger {
	return generic.NewCataloger(catalogerName).
		WithParserByGlobs(parseConanfile, "**/conanfile.txt").
		WithParserByGlobs(parseConanlock, "**/conan.lock")
}
