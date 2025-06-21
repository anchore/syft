/*
Package cpp provides a concrete Cataloger implementations for the C/C++ language ecosystem.
*/
package cpp

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// NewConanCataloger returns a new C/C++ conanfile.txt and conan.lock cataloger object.
func NewConanCataloger() pkg.Cataloger {
	return generic.NewCataloger("conan-cataloger").
		WithParserByGlobs(parseConanfile, "**/conanfile.txt").
		WithParserByGlobs(parseConanLock, "**/conan.lock")
}

// NewConanInfoCataloger returns a new C/C++ conaninfo.txt cataloger object.
func NewConanInfoCataloger() pkg.Cataloger {
	return generic.NewCataloger("conan-info-cataloger").
		WithParserByGlobs(parseConaninfo, "**/conaninfo.txt")
}

// NewVcpkgManifestCataloger return a new C/C++ vcpkg.json cataloger object.
func NewVcpkgManifestCataloger() pkg.Cataloger {
	return generic.NewCataloger("vcpkg-manifest-cataloger").WithParserByGlobs(parseVcpkgmanifest, "**/vcpkg.json")
}
