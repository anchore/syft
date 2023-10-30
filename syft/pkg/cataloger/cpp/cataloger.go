package cpp

import (
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// NewConanCataloger returns a new C/C++ conanfile.txt and conan.lock cataloger object.
func NewConanCataloger() *generic.Cataloger {
	return generic.NewCataloger("conan-cataloger").
		WithParserByGlobs(parseConanfile, "**/conanfile.txt").
		WithParserByGlobs(parseConanlock, "**/conan.lock")
}

// NewConanInfoCataloger returns a new C/C++ conaninfo.txt cataloger object.
func NewConanInfoCataloger() *generic.Cataloger {
	return generic.NewCataloger("conan-info-cataloger").
		WithParserByGlobs(parseConaninfo, "**/conaninfo.txt")
}
